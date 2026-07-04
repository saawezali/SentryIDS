import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.tree import DecisionTreeClassifier
from sklearn.neighbors import KNeighborsClassifier
from sklearn.svm import LinearSVC
from sklearn.metrics import f1_score, classification_report
from sklearn.pipeline import Pipeline
from imblearn.over_sampling import SMOTE
from skl2onnx import convert_sklearn
from skl2onnx.common.data_types import FloatTensorType
import warnings
import os

from preprocess import MODEL_DIR, preprocess

warnings.filterwarnings("ignore")


def train_and_evaluate(models, X_train, y_train, X_test, y_test):
    """
    Train each model, evaluate on the test set, and return the best one
    by macro-averaged F1-score. Macro-averaging treats each class equally,
    which matters here because R2L and U2R have far fewer samples than DoS.
    If we used accuracy, a model that ignores rare classes would score 98%+
    and look great while missing the most dangerous attack types.
    """
    results = {}

    for name, model in models.items():
        print(f"\nTraining {name}...")
        model.fit(X_train, y_train)

        y_pred = model.predict(X_test)
        f1 = f1_score(y_test, y_pred, average="macro")
        results[name] = (f1, model)

        print(f"  F1 (macro): {f1:.4f}")
        print(classification_report(
            y_test, y_pred,
            target_names=["Normal", "DoS", "Probe", "R2L", "U2R"],
            zero_division=0
        ))

    best_name = max(results, key=lambda k: results[k][0])
    best_f1, best_model = results[best_name]
    print(f"\nBest model: {best_name} (F1={best_f1:.4f})")
    return best_name, best_model


def export_to_onnx(model, output_path):
    """
    Convert the trained scikit-learn model to ONNX format.
    The FloatTensorType([None, 41]) declaration means:
      - None rows (any batch size is accepted)
      - 41 columns (our 41 NSL-KDD features)
    This shape must match the [41]float32 array our Go code sends to inference.
    """
    initial_type = [("float_input", FloatTensorType([None, 41]))]
    onnx_model = convert_sklearn(
        model,
        "SentryIDS",
        initial_type,
        options={id(model): {"zipmap": False}},
    )

    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "wb") as f:
        f.write(onnx_model.SerializeToString())
    print(f"Exported ONNX model to {output_path}")


if __name__ == "__main__":
    X_train, y_train, X_test, y_test, scaler = preprocess()

    print("\nApplying SMOTE to balance training classes...")
    smote = SMOTE(random_state=42)
    X_train_balanced, y_train_balanced = smote.fit_resample(X_train, y_train)
    print(f"Balanced training set: {X_train_balanced.shape}")

    models = {
        "RandomForest":  RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1),
        "DecisionTree":  DecisionTreeClassifier(random_state=42),
        "KNN":           KNeighborsClassifier(n_neighbors=5, n_jobs=-1),
        "LinearSVC":     LinearSVC(random_state=42, max_iter=2000),
    }

    best_name, best_model = train_and_evaluate(
        models, X_train_balanced, y_train_balanced, X_test, y_test
    )

    export_to_onnx(best_model, MODEL_DIR / "ids_model.onnx")
    print("\nTraining pipeline complete.")
