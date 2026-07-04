import numpy as np
import onnxruntime as rt
from sklearn.metrics import f1_score, confusion_matrix
import seaborn as sns
import matplotlib.pyplot as plt

from preprocess import BASE_DIR, MODEL_DIR, preprocess


def verify_parity(sklearn_model, onnx_path, X_test):
    """
    Run the same inputs through both the original sklearn model and the
    exported ONNX model, and assert the predictions are identical.
    Even a single disagreement means the export is broken.
    """
    sklearn_preds = sklearn_model.predict(X_test)

    sess = rt.InferenceSession(onnx_path)

    onnx_inputs = {"float_input": X_test.astype(np.float32)}

    onnx_preds = sess.run(["label"], onnx_inputs)[0]

    mismatches = np.sum(sklearn_preds != onnx_preds)
    total = len(sklearn_preds)

    if mismatches == 0:
        print(f"✓ Parity check passed: all {total} predictions match")
    else:
        print(f"✗ Parity check FAILED: {mismatches}/{total} predictions differ")
        raise RuntimeError("ONNX export produced different predictions than sklearn model")

    return onnx_preds


def plot_confusion_matrix(y_true, y_pred, title="Confusion Matrix"):
    labels = ["Normal", "DoS", "Probe", "R2L", "U2R"]
    cm = confusion_matrix(y_true, y_pred)

    plt.figure(figsize=(8, 6))
    sns.heatmap(cm, annot=True, fmt="d", cmap="Blues",
                xticklabels=labels, yticklabels=labels)
    plt.title(title)
    plt.ylabel("True Label")
    plt.xlabel("Predicted Label")
    plt.tight_layout()
    plt.savefig(BASE_DIR / "confusion_matrix.png", dpi=150)
    print("Saved confusion_matrix.png")


if __name__ == "__main__":
    from train import export_to_onnx, train_and_evaluate
    from preprocess import preprocess
    from imblearn.over_sampling import SMOTE
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.tree import DecisionTreeClassifier
    from sklearn.neighbors import KNeighborsClassifier
    from sklearn.svm import LinearSVC

    X_train, y_train, X_test, y_test, _ = preprocess()

    smote = SMOTE(random_state=42)
    X_train_bal, y_train_bal = smote.fit_resample(X_train, y_train)

    models = {
        "RandomForest": RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1),
        "DecisionTree": DecisionTreeClassifier(random_state=42),
        "KNN":          KNeighborsClassifier(n_neighbors=5, n_jobs=-1),
        "LinearSVC":    LinearSVC(random_state=42, max_iter=2000),
    }

    best_name, best_model = train_and_evaluate(
        models, X_train_bal, y_train_bal, X_test, y_test
    )

    # Evaluate the model selected in this run, not a stale file from an older run.
    model_path = MODEL_DIR / "ids_model.onnx"
    export_to_onnx(best_model, model_path)

    print("\nRunning parity check...")
    onnx_preds = verify_parity(best_model, model_path, X_test)

    macro_f1 = f1_score(y_test, onnx_preds, average="macro")
    print(f"ONNX model macro F1 on test set: {macro_f1:.4f}")

    plot_confusion_matrix(y_test, onnx_preds)
