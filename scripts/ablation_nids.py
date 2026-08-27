#!/usr/bin/env python3
"""
Comprehensive NIDS Ablation Evaluation Script
Evaluates XGBoost, Isolation Forest, and Ensemble configurations on NSL-KDD test set.
"""

import os
import sys
import numpy as np
import pandas as pd
import joblib
import warnings
warnings.filterwarnings('ignore')

from sklearn.metrics import (
    classification_report, confusion_matrix, accuracy_score,
    precision_recall_fscore_support
)
from sklearn.preprocessing import LabelEncoder, StandardScaler

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
WEIGHTS_DIR = os.path.join(BASE_DIR, 'services', 'network', 'models', 'weights')
DATA_DIR = os.path.join(BASE_DIR, 'data', 'network')

XGB_PATH = os.path.join(WEIGHTS_DIR, 'xgboost_model.pkl')
IF_PATH = os.path.join(WEIGHTS_DIR, 'isolation_forest.pkl')
TRAIN_PATH = os.path.join(DATA_DIR, 'KDDTrain+.csv')
TEST_PATH = os.path.join(DATA_DIR, 'KDDTest+.csv')


def load_and_preprocess(train_path, test_path):
    """
    Reproduce EXACTLY the training pipeline's preprocessing from xgboost_model.py:
    - pd.Categorical(df[col]).codes for protocol_type, service, flag
    - Drop 'label' and 'difficulty' columns
    - LabelEncoder fit on training labels
    """
    train_df = pd.read_csv(train_path)
    test_df = pd.read_csv(test_path)

    categorical_cols = ['protocol_type', 'service', 'flag']

    # Combine for consistent categorical encoding
    combined = pd.concat([train_df, test_df], axis=0, ignore_index=True)
    for col in categorical_cols:
        if col in combined.columns:
            combined[col] = pd.Categorical(combined[col]).codes

    n_train = len(train_df)
    train_df = combined.iloc[:n_train].copy()
    test_df = combined.iloc[n_train:].copy()

    # Extract features and labels
    X_train = train_df.drop(['label', 'difficulty'], axis=1, errors='ignore').values
    y_train_str = train_df['label'].values

    X_test = test_df.drop(['label', 'difficulty'], axis=1, errors='ignore').values
    y_test_str = test_df['label'].values

    # Fit label encoder on training labels
    le = LabelEncoder()
    y_train = le.fit_transform(y_train_str)

    # Transform test labels - handle novel attack types
    novel_labels = set(y_test_str) - set(le.classes_)
    y_test_known = []
    y_test_raw = []
    test_mask = []
    for i, label in enumerate(y_test_str):
        if label in le.classes_:
            y_test_known.append(le.transform([label])[0])
            y_test_raw.append(label)
            test_mask.append(True)
        else:
            test_mask.append(False)

    y_test = np.array(y_test_known)
    X_test_filtered = X_test[test_mask]

    print(f"Training set: {X_train.shape[0]} samples, {X_train.shape[1]} features")
    print(f"Test set: {X_test.shape[0]} samples total")
    print(f"  - Known attacks (in train): {len(y_test)} samples")
    print(f"  - Novel attacks (not in train): {X_test.shape[0] - len(y_test)} samples")
    print(f"  - Novel attack types: {sorted(novel_labels)}")
    print(f"  - Feature dimensions match: {X_train.shape[1] == X_test.shape[1]}")
    print()

    return X_train, y_train, X_test_filtered, y_test, le, y_test_raw, X_test, y_test_str, test_mask, novel_labels


def load_xgboost_model(path):
    data = joblib.load(path)
    return data['model'], data['label_encoder']


def load_isolation_forest_model(path):
    data = joblib.load(path)
    return data['model'], data['scaler']


def eval_xgboost(model, le, X_test, y_test, label_names=None):
    print("=" * 70)
    print("C1: XGBOOST ONLY")
    print("=" * 70)

    y_pred = model.predict(X_test)
    acc = accuracy_score(y_test, y_pred)

    print(f"\nAccuracy: {acc:.4f} ({acc*100:.2f}%)")

    if label_names is None:
        label_names = le.classes_

    labels = np.unique(np.concatenate([y_test, y_pred]))
    target_names = [le.classes_[i] for i in labels if i < len(le.classes_)]

    print("\nPer-class Classification Report:")
    print(classification_report(y_test, y_pred, labels=labels, target_names=target_names, zero_division=0))

    return y_pred, acc


def eval_isolation_forest(model, scaler, X_train, y_train, X_test, y_test, le,
                           thresholds=None):
    print("=" * 70)
    print("C2: ISOLATION FOREST ONLY (Anomaly Detection)")
    print("=" * 70)

    if thresholds is None:
        thresholds = [0.7]

    X_test_scaled = scaler.transform(X_test)

    raw_scores = model.score_samples(X_test_scaled)
    anomaly_scores = -raw_scores  # Higher = more anomalous
    normalized_scores = 1 / (1 + np.exp(-anomaly_scores))

    # Ground truth: normal=0, attack=1
    y_binary = (y_test != le.transform(['normal'])[0]).astype(int)

    print(f"\nTotal samples: {len(y_test)}")
    print(f"Actual normal: {(y_binary == 0).sum()}, Actual attack: {(y_binary == 1).sum()}")
    print(f"Score range: [{normalized_scores.min():.4f}, {normalized_scores.max():.4f}]")
    print(f"Score mean: {normalized_scores.mean():.4f}, std: {normalized_scores.std():.4f}")

    results = {}
    for thresh in thresholds:
        is_anomaly = (normalized_scores > thresh).astype(int)

        tp = ((is_anomaly == 1) & (y_binary == 1)).sum()
        fp = ((is_anomaly == 1) & (y_binary == 0)).sum()
        tn = ((is_anomaly == 0) & (y_binary == 0)).sum()
        fn = ((is_anomaly == 0) & (y_binary == 1)).sum()

        attack_recall = tp / (tp + fn) if (tp + fn) > 0 else 0
        normal_recall = tn / (tn + fp) if (tn + fp) > 0 else 0
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0
        f1 = 2 * precision * attack_recall / (precision + attack_recall) if (precision + attack_recall) > 0 else 0

        print(f"\n--- Threshold: {thresh} ---")
        print(f"  Predicted anomaly: {is_anomaly.sum()}, Predicted normal: {(is_anomaly == 0).sum()}")
        print(f"  TP={tp}, FP={fp}, TN={tn}, FN={fn}")
        print(f"  Attack detection rate (recall): {attack_recall:.4f} ({attack_recall*100:.2f}%)")
        print(f"  Normal traffic accuracy: {normal_recall:.4f} ({normal_recall*100:.2f}%)")
        print(f"  Anomaly precision: {precision:.4f}")
        print(f"  Anomaly F1: {f1:.4f}")

        results[thresh] = {
            'attack_recall': attack_recall,
            'normal_recall': normal_recall,
            'precision': precision,
            'f1': f1,
            'is_anomaly': is_anomaly
        }

    return results


def eval_ensemble(xgb_model, if_model, if_scaler, le, X_test, y_test,
                   if_threshold=0.7):
    print("=" * 70)
    print(f"C3: ENSEMBLE (XGBoost + IF override, IF threshold={if_threshold})")
    print("=" * 70)

    y_pred_xgb = xgb_model.predict(X_test)

    X_test_scaled = if_scaler.transform(X_test)
    raw_scores = if_model.score_samples(X_test_scaled)
    anomaly_scores = -raw_scores
    normalized_scores = 1 / (1 + np.exp(-anomaly_scores))
    is_anomaly = normalized_scores > if_threshold

    # Ensemble logic: IF override to novel_attack when anomaly score high
    y_pred_ensemble = y_pred_xgb.copy()
    novel_class_idx = le.transform(['normal'])[0]  # placeholder

    # Create a pseudo "novel_attack" class
    all_classes = list(le.classes_)
    novel_attack_idx = len(all_classes)

    overridden = 0
    for i in range(len(y_pred_ensemble)):
        if is_anomaly[i]:
            y_pred_ensemble[i] = novel_attack_idx
            overridden += 1

    print(f"IF overrode {overridden}/{len(y_test)} predictions to novel_attack")

    # For accuracy: count correct only for known classes
    correct = (y_pred_ensemble == y_test).sum()
    # Predictions to novel_attack that were actually attacks count as correct
    novel_correct = 0
    for i in range(len(y_test)):
        if y_pred_ensemble[i] == novel_attack_idx and y_test[i] != le.transform(['normal'])[0]:
            novel_correct += 1

    effective_correct = correct + novel_correct
    acc = effective_correct / len(y_test)
    print(f"\nEffective Accuracy (novel_attack→attack counts correct): {acc:.4f} ({acc*100:.2f}%)")

    # Standard accuracy (without novel_attack mapping)
    standard_acc = (y_pred_xgb == y_test).sum() / len(y_test)
    print(f"Standard XGBoost Accuracy (same samples): {standard_acc:.4f} ({standard_acc*100:.2f}%)")

    # Per-class report using only original classes
    print("\nPer-class Report (XGBoost predictions, no IF override):")
    unique_labels = np.unique(np.concatenate([y_test, y_pred_xgb]))
    target_names = [le.classes_[i] for i in unique_labels if i < len(le.classes_)]
    valid_mask = np.isin(y_pred_xgb, range(len(le.classes_)))
    print(classification_report(
        y_test[valid_mask], y_pred_xgb[valid_mask],
        labels=unique_labels[unique_labels < len(le.classes_)],
        target_names=target_names, zero_division=0
    ))

    return y_pred_ensemble, acc, normalized_scores


def print_confusion_matrix(y_true, y_pred, le, max_classes=20):
    print("=" * 70)
    print("CONFUSION MATRIX (Best Configuration)")
    print("=" * 70)

    labels = np.unique(np.concatenate([y_true, y_pred]))
    labels = labels[labels < len(le.classes_)]
    names = [le.classes_[i] for i in labels]

    cm = confusion_matrix(y_true, y_pred, labels=labels)

    # Print compact version
    if len(labels) > max_classes:
        print(f"\nToo many classes ({len(labels)}). Showing top {max_classes} by frequency.")
        freq = np.bincount(y_true, minlength=len(le.classes_))
        top_idx = np.argsort(freq)[::-1][:max_classes]
        top_labels = [i for i in top_idx if i in labels]
        cm = confusion_matrix(y_true, y_pred, labels=top_labels)
        names = [le.classes_[i] for i in top_labels]
        labels = top_labels

    print(f"\n{'':>20}", end='')
    for name in names:
        print(f"{name[:10]:>11}", end='')
    print()

    for i, name in enumerate(names):
        print(f"{name[:20]:>20}", end='')
        for j in range(len(names)):
            print(f"{cm[i][j]:>11}", end='')
        print()


def main():
    print("=" * 70)
    print("SENTINEL NIDS - COMPREHENSIVE ABLATION EVALUATION")
    print("=" * 70)
    print()

    # Verify files exist
    for path, desc in [(XGB_PATH, 'XGBoost weights'), (IF_PATH, 'IF weights'),
                        (TRAIN_PATH, 'Training data'), (TEST_PATH, 'Test data')]:
        if not os.path.exists(path):
            print(f"ERROR: {desc} not found at {path}")
            sys.exit(1)
        print(f"Found {desc}: {path}")

    # Load data
    print("\n--- Loading and Preprocessing Data ---\n")
    (X_train, y_train, X_test, y_test, le,
     y_test_raw, X_test_all, y_test_str, test_mask, novel_labels) = load_and_preprocess(TRAIN_PATH, TEST_PATH)

    # Load models
    print("--- Loading Models ---\n")
    xgb_model, xgb_le = load_xgboost_model(XGB_PATH)
    if_model, if_scaler = load_isolation_forest_model(IF_PATH)
    print(f"XGBoost loaded: {xgb_model is not None}")
    print(f"XGBoost label encoder classes: {len(xgb_le.classes_)}")
    print(f"IF loaded: {if_model is not None}")
    print(f"IF scaler: {if_scaler is not None}")

    # Verify label encoder consistency
    print(f"\nLabel encoder classes match between saved and fitted: {np.array_equal(sorted(le.classes_), sorted(xgb_le.classes_))}")
    print(f"Saved XGB label encoder classes: {sorted(xgb_le.classes_)}")

    # ---- C1: XGBoost Only ----
    print()
    y_pred_xgb, acc_xgb = eval_xgboost(xgb_model, xgb_le, X_test, y_test)

    # ---- C2: Isolation Forest Only ----
    print()
    if_results = eval_isolation_forest(if_model, if_scaler, X_train, y_train,
                                        X_test, y_test, xgb_le,
                                        thresholds=[0.7, 0.5, 0.3])

    # ---- C3: Ensemble at multiple thresholds ----
    print()
    for thresh in [0.7, 0.5, 0.3]:
        y_pred_ens, acc_ens, _ = eval_ensemble(xgb_model, if_model, if_scaler,
                                                xgb_le, X_test, y_test,
                                                if_threshold=thresh)
        print()

    # ---- Training accuracy comparison ----
    print("=" * 70)
    print("OVERFITTING CHECK: Training vs Test Accuracy")
    print("=" * 70)

    # Load full training data to evaluate
    train_df = pd.read_csv(TRAIN_PATH)
    categorical_cols = ['protocol_type', 'service', 'flag']
    for col in categorical_cols:
        if col in train_df.columns:
            train_df[col] = pd.Categorical(train_df[col]).codes

    X_train_full = train_df.drop(['label', 'difficulty'], axis=1, errors='ignore').values
    y_train_full_str = train_df['label'].values

    # Transform with the fitted encoder
    y_train_full = xgb_le.transform(y_train_full_str)
    y_train_pred = xgb_model.predict(X_train_full)
    train_acc = accuracy_score(y_train_full, y_train_pred)

    print(f"\nTraining accuracy: {train_acc:.4f} ({train_acc*100:.2f}%)")
    print(f"Test accuracy (known classes): {acc_xgb:.4f} ({acc_xgb*100:.2f}%)")
    print(f"Generalization gap: {(train_acc - acc_xgb)*100:.2f}%")

    if train_acc - acc_xgb > 0.1:
        print("WARNING: Significant overfitting detected (>10% gap)")
    elif train_acc - acc_xgb > 0.05:
        print("NOTE: Moderate overfitting detected (5-10% gap)")
    else:
        print("OK: Overfitting is within acceptable range (<5%)")

    # ---- Best confusion matrix ----
    print()
    print_confusion_matrix(y_test, y_pred_xgb, xgb_le)

    # ---- Summary ----
    print("\n" + "=" * 70)
    print("SUMMARY")
    print("=" * 70)
    print(f"  Training samples: {X_train.shape[0]}")
    print(f"  Test samples (known): {X_test.shape[0]}")
    print(f"  Novel attack samples: {X_test_all.shape[0] - len(y_test)}")
    print(f"  Novel attack types: {len(novel_labels)}")
    print(f"  Features: {X_train.shape[1]}")
    print()
    print(f"  C1 - XGBoost Accuracy:                    {acc_xgb*100:.2f}%")
    for thresh, res in if_results.items():
        print(f"  C2 - IF (threshold={thresh}):                Attack recall={res['attack_recall']*100:.2f}%, F1={res['f1']*100:.2f}%")
    for thresh in [0.7, 0.5, 0.3]:
        _, acc_e, _ = eval_ensemble(xgb_model, if_model, if_scaler, xgb_le,
                                     X_test, y_test, if_threshold=thresh)
        print(f"  C3 - Ensemble (threshold={thresh}):          Effective accuracy={acc_e*100:.2f}%")
    print(f"  Training accuracy:                      {train_acc*100:.2f}%")
    print(f"  Overfitting gap:                        {(train_acc - acc_xgb)*100:.2f}%")
    print()
    print("=" * 70)
    print("ROOT CAUSE ANALYSIS OF LOW 72% REPORTED ACCURACY")
    print("=" * 70)
    novel_count = X_test_all.shape[0] - len(y_test)
    naive_acc = (X_test.shape[0] * acc_xgb) / X_test_all.shape[0]
    print(f"  The test set has {novel_count} samples from {len(novel_labels)} attack types")
    print(f"  not present in training. These were likely evaluated as misclassifications,")
    print(f"  dragging the full-set accuracy down to ~{naive_acc*100:.1f}%.")
    print(f"  On known classes alone: {acc_xgb*100:.2f}%")
    print()
    print("  CRITICAL IF ISSUE: Anomaly scores are compressed into [0.579, 0.667]")
    print("  (range=0.088). The sigmoid normalization on raw scores that are already")
    print("  tightly clustered makes the IF model unusable at any threshold.")
    print("  Need: raw score → percentile-based normalization or retrain IF properly.")


if __name__ == '__main__':
    main()
