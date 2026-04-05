import numpy as np
import json
import os
from sklearn.ensemble import RandomForestClassifier
from sklearn.tree import DecisionTreeClassifier
from sklearn.neighbors import KNeighborsClassifier
from sklearn.svm import SVC
from sklearn.metrics import f1_score, classification_report
from skl2onnx import convert_sklearn
from skl2onnx.common.data_types import FloatTensorType

CLASS_NAMES = ['Normal', 'DoS', 'Probe', 'R2L', 'U2R']

def train_and_evaluate():
    print("Loading preprocessed data...")
    X_train = np.load('data/X_train.npy')
    y_train = np.load('data/y_train.npy')
    X_test  = np.load('data/X_test.npy')
    y_test  = np.load('data/y_test.npy')

    models = {
        'RandomForest': RandomForestClassifier(n_estimators=100, n_jobs=-1, random_state=42),
        'DecisionTree': DecisionTreeClassifier(random_state=42),
        'KNN':          KNeighborsClassifier(n_neighbors=5, n_jobs=-1),
    }

    best_model = None
    best_f1 = 0
    best_name = ''
    results = {}

    for name, model in models.items():
        print(f"\nTraining {name}...")
        model.fit(X_train, y_train)
        preds = model.predict(X_test)
        f1 = f1_score(y_test, preds, average='macro')
        results[name] = f1
        print(f"  {name} F1 (macro): {f1:.4f}")

        if f1 > best_f1:
            best_f1 = f1
            best_model = model
            best_name = name

    print(f"\n✓ Best model: {best_name} (F1={best_f1:.4f})")
    print("\nClassification Report (best model):")
    print(classification_report(y_test, best_model.predict(X_test), target_names=CLASS_NAMES))

    print("\nExporting to ONNX...")
    os.makedirs('../models', exist_ok=True)

    initial_type = [("float_input", FloatTensorType([None, 41]))]
    onnx_model = convert_sklearn(best_model, "SentryIDS", initial_type)

    with open('../models/ids_model.onnx', 'wb') as f:
        f.write(onnx_model.SerializeToString())

    print("✓ Model exported to ../models/ids_model.onnx")

    with open('../models/training_results.json', 'w') as f:
        json.dump({'best_model': best_name, 'best_f1': best_f1, 'all_scores': results}, f, indent=2)

if __name__ == '__main__':
    train_and_evaluate()