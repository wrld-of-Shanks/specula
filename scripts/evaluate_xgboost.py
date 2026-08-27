import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'services', 'network'))

import numpy as np
import pandas as pd
import joblib
from sklearn.metrics import (
    accuracy_score, classification_report, confusion_matrix,
    precision_score, recall_score, f1_score
)

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
XGB_PATH = os.path.join(BASE_DIR, 'services', 'network', 'models', 'weights', 'xgboost_model.pkl')
IF_PATH = os.path.join(BASE_DIR, 'services', 'network', 'models', 'weights', 'isolation_forest.pkl')
TEST_PATH = os.path.join(BASE_DIR, 'data', 'network', 'KDDTest+.csv')

CATEGORICAL_COLS = ['protocol_type', 'service', 'flag']


def load_data(path):
    df = pd.read_csv(path)
    for col in CATEGORICAL_COLS:
        if col in df.columns:
            df[col] = pd.Categorical(df[col]).codes
    X = df.drop(['label', 'difficulty'], axis=1, errors='ignore').values
    y = df['label'].values
    return X, y


def load_models():
    xgb_data = joblib.load(XGB_PATH)
    if_data = joblib.load(IF_PATH)
    return (
        xgb_data['model'], xgb_data['label_encoder'],
        if_data['model'], if_data['scaler']
    )


def ensemble_predict(xgb_model, le, if_model, scaler, X, threshold=0.7):
    xgb_preds_encoded = xgb_model.predict(X)
    xgb_preds = le.inverse_transform(xgb_preds_encoded)

    X_scaled = scaler.transform(X)
    if_preds = if_model.predict(X_scaled)
    if_scores = -if_model.score_samples(X_scaled)

    norm_scores = 1 / (1 + np.exp(-if_scores))

    ensemble_preds = []
    novel_overrides = 0
    for i in range(len(X)):
        if if_preds[i] == -1 and norm_scores[i] > threshold:
            ensemble_preds.append('novel_attack')
            novel_overrides += 1
        else:
            ensemble_preds.append(xgb_preds[i])

    return (
        xgb_preds,
        np.array(ensemble_preds),
        if_preds,
        norm_scores,
        novel_overrides
    )


def print_metrics(name, y_true, y_pred, classes):
    print(f"\n{'=' * 70}")
    print(f"  {name}")
    print(f"{'=' * 70}")

    acc = accuracy_score(y_true, y_pred)
    print(f"\nOverall Accuracy: {acc:.4f} ({acc*100:.2f}%)")

    all_labels = sorted(set(y_true) | set(y_pred))
    present_names = [c for c in classes if c in all_labels]

    print(f"\nClassification Report:")
    print(classification_report(
        y_true, y_pred,
        labels=present_names,
        target_names=present_names,
        zero_division=0
    ))

    print(f"Confusion Matrix ({len(present_names)} classes):")
    cm = confusion_matrix(y_true, y_pred, labels=present_names)
    header = ''.join(f"{c[:8]:>9}" for c in present_names)
    print(f"{'':>9}{header}")
    for i, row_label in enumerate(present_names):
        row = ''.join(f"{cm[i][j]:>9}" for j in range(len(present_names)))
        print(f"{row_label[:8]:>9}{row}")

    return acc


def main():
    print("=" * 70)
    print("  Specula Network Intrusion Detection - Full Evaluation")
    print("=" * 70)

    print("\nLoading test set...")
    X_test, y_test = load_data(TEST_PATH)
    print(f"  Test samples: {X_test.shape[0]}, Features: {X_test.shape[1]}")

    print("Loading models...")
    xgb_model, le, if_model, scaler = load_models()
    n_classes = len(le.classes_)
    print(f"  XGBoost classes: {n_classes} -> {list(le.classes_)}")

    xgb_preds, ensemble_preds, if_preds, if_scores, novel_overrides = ensemble_predict(
        xgb_model, le, if_model, scaler, X_test
    )

    all_classes = sorted(le.classes_)
    all_classes_with_novel = sorted(set(all_classes) | {'novel_attack'})

    xgb_acc = print_metrics("XGBoost Alone", y_test, xgb_preds, all_classes)
    ens_acc = print_metrics("XGBoost + IsolationForest Ensemble", y_test, ensemble_preds, all_classes_with_novel)

    print(f"\n{'=' * 70}")
    print("  Isolation Forest Contribution")
    print(f"{'=' * 70}")
    print(f"  Total samples: {len(y_test)}")
    print(f"  IF flagged as anomaly (-1): {(if_preds == -1).sum()}")
    print(f"  IF flagged as normal  (+1): {(if_preds == 1).sum()}")
    print(f"  Anomaly score range: {if_scores.min():.4f} to {if_scores.max():.4f}")
    print(f"  Mean anomaly score:  {if_scores.mean():.4f}")
    print(f"\n  Novel attack overrides (IF anomaly + score>0.7): {novel_overrides}")
    real_novel = (y_test == 'novel_attack').sum()
    if real_novel > 0:
        print(f"  True novel_attack samples in test set: {real_novel}")
    else:
        print(f"  True novel_attack samples in test set: 0 (none in KDDTest+)")
        print(f"  -> All novel_attack predictions are false positives by design,")
        print(f"     but these catch genuinely unseen patterns at inference time.")

    print(f"\n{'=' * 70}")
    print("  Comparison: XGBoost Alone vs XGBoost+IF Ensemble")
    print(f"{'=' * 70}")
    print(f"  {'Metric':<30} {'XGBoost':>12} {'Ensemble':>12}")
    print(f"  {'-'*54}")
    print(f"  {'Accuracy':<30} {xgb_acc:>11.4f} {ens_acc:>11.4f}")

    xgb_prec = precision_score(y_test, xgb_preds, average='weighted', zero_division=0)
    ens_prec = precision_score(y_test, ensemble_preds, average='weighted', zero_division=0)
    print(f"  {'Weighted Precision':<30} {xgb_prec:>11.4f} {ens_prec:>11.4f}")

    xgb_rec = recall_score(y_test, xgb_preds, average='weighted', zero_division=0)
    ens_rec = recall_score(y_test, ensemble_preds, average='weighted', zero_division=0)
    print(f"  {'Weighted Recall':<30} {xgb_rec:>11.4f} {ens_rec:>11.4f}")

    xgb_f1 = f1_score(y_test, xgb_preds, average='weighted', zero_division=0)
    ens_f1 = f1_score(y_test, ensemble_preds, average='weighted', zero_division=0)
    print(f"  {'Weighted F1':<30} {xgb_f1:>11.4f} {ens_f1:>11.4f}")

    xgb_macros = f1_score(y_test, xgb_preds, average='macro', zero_division=0)
    ens_macros = f1_score(y_test, ensemble_preds, average='macro', zero_division=0)
    print(f"  {'Macro F1':<30} {xgb_macros:>11.4f} {ens_macros:>11.4f}")

    print(f"\n  Delta Accuracy: {(ens_acc - xgb_acc)*100:+.2f}%")
    print(f"  Novel overrides: {novel_overrides} / {len(y_test)} ({novel_overrides/len(y_test)*100:.2f}%)")
    print()


if __name__ == '__main__':
    main()
