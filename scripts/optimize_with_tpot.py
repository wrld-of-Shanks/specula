"""
TPOT AutoML Pipeline Optimization for HORUS NIDS
Uses genetic programming to find the best ML pipeline for intrusion detection.
"""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'backend', 'services', 'network'))

import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import (
    classification_report, accuracy_score, f1_score, log_loss
)
import joblib
import time

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(BASE_DIR, 'data', 'network')
WEIGHTS_DIR = os.path.join(BASE_DIR, 'backend', 'services', 'network', 'models', 'weights')

TRAIN_PATH = os.path.join(DATA_DIR, 'KDDTrain+.csv')
TEST_PATH = os.path.join(DATA_DIR, 'KDDTest+.csv')
SAVE_PATH = os.path.join(WEIGHTS_DIR, 'tpot_pipeline.pkl')

CATEGORICAL_COLS = ['protocol_type', 'service', 'flag']


def load_and_encode(csv_path):
    df = pd.read_csv(csv_path)
    for col in CATEGORICAL_COLS:
        if col in df.columns:
            df[col] = pd.Categorical(df[col]).codes
    X = df.drop(['label', 'difficulty'], axis=1, errors='ignore').values
    y_str = df['label'].values
    return X, y_str


def optimize_with_tpot(
    generations=50,
    population_size=50,
    timeout_mins=30,
    cv=5,
    n_jobs=-1,
    verbosity=2,
    random_state=42,
):
    from tpot import TPOTClassifier

    print("=" * 60)
    print("TPOT AutoML PIPELINE OPTIMIZATION — HORUS NIDS")
    print("=" * 60)

    X_train_full, y_train_str = load_and_encode(TRAIN_PATH)
    le = LabelEncoder()
    y_train_full = le.fit_transform(y_train_str)

    print(f"Training set: {X_train_full.shape[0]} samples, {X_train_full.shape[1]} features")
    print(f"Number of classes: {len(le.classes_)}")

    X_tr, X_val, y_tr, y_val = train_test_split(
        X_train_full, y_train_full, test_size=0.2, random_state=random_state, stratify=y_train_full
    )

    print(f"\nTrain split: {len(y_tr)} | Validation split: {len(y_val)}")
    print(f"\nTPOT Configuration:")
    print(f"  Generations:      {generations}")
    print(f"  Population size:  {population_size}")
    print(f"  Timeout:          {timeout_mins} minutes")
    print(f"  CV folds:         {cv}")
    print(f"  Parallelism:      {'all cores' if n_jobs == -1 else f'{n_jobs} cores'}")

    checkpoint_dir = os.path.join(BASE_DIR, 'scripts', 'tpot_checkpoints')
    os.makedirs(checkpoint_dir, exist_ok=True)

    tpot = TPOTClassifier(
        generations=generations,
        population_size=population_size,
        timeout=timeout_mins * 60,
        cv=cv,
        n_jobs=n_jobs,
        scoring='accuracy',
        verbosity=verbosity,
        random_state=random_state,
        periodic_checkpoint_folder=checkpoint_dir,
        warm_start=False,
    )

    print(f"\nStarting TPOT optimization...")
    start_time = time.time()
    tpot.fit(X_tr, y_tr)
    elapsed = time.time() - start_time
    print(f"\nTPOT optimization completed in {elapsed/60:.1f} minutes")

    val_pred = tpot.predict(X_val)
    val_acc = accuracy_score(y_val, val_pred)
    print(f"\n[TPOT] Validation accuracy: {val_acc:.4f} ({val_acc*100:.2f}%)")

    print(f"\nBest pipeline found:")
    print(f"  {tpot.fitted_pipeline_}")

    print(f"\n{'='*60}")
    print("EVALUATION ON KDDTest+ (held-out test set)")
    print(f"{'='*60}")

    X_test, y_test_str = load_and_encode(TEST_PATH)
    unknown_labels = set(y_test_str) - set(le.classes_)
    known_mask = np.array([s in le.classes_ for s in y_test_str])
    X_test_known = X_test[known_mask]
    y_test_known = le.transform(y_test_str[known_mask])

    print(f"KDDTest+ total samples: {len(y_test_str)}")
    print(f"  Known-class samples: {known_mask.sum()}")
    if unknown_labels:
        print(f"  Novel attacks (excluded): {sorted(unknown_labels)} ({(~known_mask).sum()} samples)")

    y_pred = tpot.predict(X_test_known)

    acc = accuracy_score(y_test_known, y_pred)
    macro_f1 = f1_score(y_test_known, y_pred, average='macro')
    weighted_f1 = f1_score(y_test_known, y_pred, average='weighted')

    print(f"\nAccuracy:    {acc:.4f} ({acc*100:.2f}%)")
    print(f"Macro F1:    {macro_f1:.4f}")
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

    os.makedirs(os.path.dirname(SAVE_PATH), exist_ok=True)
    joblib.dump({
        'pipeline': tpot.fitted_pipeline_,
        'label_encoder': le,
        'accuracy': acc,
        'macro_f1': macro_f1,
        'weighted_f1': weighted_f1,
        'generations': generations,
        'population_size': population_size,
        'elapsed_seconds': elapsed,
        'best_pipeline_str': str(tpot.fitted_pipeline_),
    }, SAVE_PATH)
    print(f"\nTPOT pipeline saved to: {SAVE_PATH}")

    tpot.export(os.path.join(BASE_DIR, 'scripts', 'tpot_best_pipeline.py'))
    print(f"Pipeline Python code exported to: scripts/tpot_best_pipeline.py")

    return tpot


if __name__ == '__main__':
    import argparse

    parser = argparse.ArgumentParser(description='TPOT AutoML for HORUS NIDS')
    parser.add_argument('--generations', type=int, default=50, help='Number of generations')
    parser.add_argument('--population', type=int, default=50, help='Population size')
    parser.add_argument('--timeout', type=int, default=30, help='Timeout in minutes')
    parser.add_argument('--cv', type=int, default=5, help='Cross-validation folds')
    parser.add_argument('--cores', type=int, default=-1, help='CPU cores (-1 = all)')
    args = parser.parse_args()

    optimize_with_tpot(
        generations=args.generations,
        population_size=args.population,
        timeout_mins=args.timeout,
        cv=args.cv,
        n_jobs=args.cores,
    )
