import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'services', 'network'))

import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import (
    classification_report, confusion_matrix, accuracy_score,
    f1_score, log_loss
)
import xgboost as xgb
import joblib

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(BASE_DIR, 'data', 'network')
WEIGHTS_DIR = os.path.join(BASE_DIR, 'services', 'network', 'models', 'weights')

TRAIN_PATH = os.path.join(DATA_DIR, 'KDDTrain+.csv')
TEST_PATH = os.path.join(DATA_DIR, 'KDDTest+.csv')
SAVE_PATH = os.path.join(WEIGHTS_DIR, 'xgboost_model.pkl')

CATEGORICAL_COLS = ['protocol_type', 'service', 'flag']


def load_and_encode(csv_path):
    df = pd.read_csv(csv_path)
    for col in CATEGORICAL_COLS:
        if col in df.columns:
            df[col] = pd.Categorical(df[col]).codes
    X = df.drop(['label', 'difficulty'], axis=1, errors='ignore').values
    y_str = df['label'].values
    return X, y_str


def fit_label_encoder(y_train_str):
    le = LabelEncoder()
    y_train = le.fit_transform(y_train_str)
    return le, y_train


def train_xgboost():
    print("=" * 60)
    print("TRAINING XGBOOST CLASSIFIER (tuned)")
    print("=" * 60)

    X_train_full, y_train_str = load_and_encode(TRAIN_PATH)
    le, y_train_full = fit_label_encoder(y_train_str)

    print(f"Training set: {X_train_full.shape[0]} samples, {X_train_full.shape[1]} features")
    print(f"Number of classes: {len(le.classes_)}")
    unique, counts = np.unique(y_train_full, return_counts=True)
    for cls_idx, count in zip(unique, counts):
        print(f"  {le.classes_[cls_idx]}: {count} ({count/len(y_train_full)*100:.1f}%)")

    X_tr, X_val, y_tr, y_val = train_test_split(
        X_train_full, y_train_full, test_size=0.2, random_state=42, stratify=y_train_full
    )

    n_classes = len(le.classes_)
    class_counts = np.bincount(y_tr)
    total = len(y_tr)
    scale_pos_weight = total / (n_classes * class_counts)

    print(f"\nTraining XGBoost (tuned hyperparameters)...")
    print(f"  max_depth: 6, learning_rate: 0.05, n_estimators: 400")
    print(f"  min_child_weight: 3, subsample: 0.8, colsample_bytree: 0.8")

    model = xgb.XGBClassifier(
        objective='multi:softprob',
        num_class=n_classes,
        max_depth=6,
        learning_rate=0.05,
        n_estimators=400,
        min_child_weight=3,
        subsample=0.8,
        colsample_bytree=0.8,
        gamma=0.1,
        scale_pos_weight=scale_pos_weight.tolist(),
        eval_metric='mlogloss',
        early_stopping_rounds=30,
        random_state=42,
        use_label_encoder=False
    )

    model.fit(
        X_tr, y_tr,
        eval_set=[(X_val, y_val)],
        verbose=False
    )

    val_pred = model.predict(X_val)
    val_acc = accuracy_score(y_val, val_pred)
    print(f"\n[Training monitor] Validation split accuracy: {val_acc:.4f} ({val_acc*100:.2f}%)")

    os.makedirs(os.path.dirname(SAVE_PATH), exist_ok=True)
    joblib.dump({'model': model, 'label_encoder': le}, SAVE_PATH)
    print(f"Model saved to: {SAVE_PATH}")

    print(f"\n{'='*60}")
    print("EVALUATION ON KDDTest+ (held-out test set)")
    print(f"{'='*60}")

    X_test, y_test_str = load_and_encode(TEST_PATH)

    unknown_labels = set(y_test_str) - set(le.classes_)
    known_mask = np.array([s in le.classes_ for s in y_test_str])
    X_test_known = X_test[known_mask]
    y_test_known = le.transform(y_test_str[known_mask])

    print(f"\nKDDTest+ total samples: {len(y_test_str)}")
    print(f"  Known-class samples (in label encoder): {known_mask.sum()}")
    if unknown_labels:
        print(f"  Novel attack types (excluded from eval): {sorted(unknown_labels)} ({(~known_mask).sum()} samples)")

    y_pred = model.predict(X_test_known)
    y_pred_proba = model.predict_proba(X_test_known)

    acc = accuracy_score(y_test_known, y_pred)
    macro_f1 = f1_score(y_test_known, y_pred, average='macro')
    weighted_f1 = f1_score(y_test_known, y_pred, average='weighted')

    print(f"\nAccuracy:  {acc:.4f} ({acc*100:.2f}%)")
    print(f"Macro F1:  {macro_f1:.4f}")
    print(f"Weighted F1: {weighted_f1:.4f}")

    all_classes = sorted(set(y_test_known) | set(y_pred))
    target_names = [le.classes_[i] for i in all_classes]
    print(f"\nClassification Report ({known_mask.sum()} samples, {len(all_classes)} classes):")
    print(classification_report(
        y_test_known, y_pred,
        labels=all_classes,
        target_names=target_names,
        zero_division=0
    ))

    print("Confusion Matrix:")
    cm = confusion_matrix(y_test_known, y_pred)
    print(cm)

    return model, le


if __name__ == '__main__':
    model, le = train_xgboost()
