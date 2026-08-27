import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'services', 'network'))

import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import joblib

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(BASE_DIR, 'data', 'network')
WEIGHTS_DIR = os.path.join(BASE_DIR, 'services', 'network', 'models', 'weights')

TRAIN_PATH = os.path.join(DATA_DIR, 'KDDTrain+.csv')
TEST_PATH = os.path.join(DATA_DIR, 'KDDTest+.csv')
SAVE_PATH = os.path.join(WEIGHTS_DIR, 'isolation_forest.pkl')

CATEGORICAL_COLS = ['protocol_type', 'service', 'flag']


def load_and_encode(csv_path):
    df = pd.read_csv(csv_path)
    for col in CATEGORICAL_COLS:
        if col in df.columns:
            df[col] = pd.Categorical(df[col]).codes
    return df


def percentile_normalize(raw_score, percentiles):
    p50 = percentiles['p50']
    p95 = percentiles['p95']
    p99 = percentiles['p99']
    if raw_score <= p50:
        return 0.0
    elif raw_score <= p95:
        return 0.3 + 0.4 * (raw_score - p50) / (p95 - p50)
    elif raw_score <= p99:
        return 0.7 + 0.2 * (raw_score - p95) / (p99 - p95)
    else:
        return min(0.9 + 0.1 * (raw_score - p99) / (p99 * 0.5 + 1e-10), 1.0)


def train_isolation_forest():
    print("=" * 60)
    print("TRAINING ISOLATION FOREST (percentile normalization)")
    print("=" * 60)

    train_df = load_and_encode(TRAIN_PATH)
    normal_mask = train_df['label'] == 'normal'
    X_normal = train_df.loc[normal_mask].drop(['label', 'difficulty'], axis=1, errors='ignore').values

    print(f"Training on normal traffic only: {X_normal.shape[0]} / {len(train_df)} samples")

    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X_normal)

    print(f"\nTraining Isolation Forest (contamination=0.1, n_estimators=200)...")

    model = IsolationForest(
        contamination=0.1,
        n_estimators=200,
        max_samples='auto',
        random_state=42,
        n_jobs=-1
    )
    model.fit(X_scaled)

    normal_scores = -model.score_samples(X_scaled)
    score_percentiles = {
        'p50': float(np.percentile(normal_scores, 50)),
        'p75': float(np.percentile(normal_scores, 75)),
        'p90': float(np.percentile(normal_scores, 90)),
        'p95': float(np.percentile(normal_scores, 95)),
        'p99': float(np.percentile(normal_scores, 99)),
        'mean': float(normal_scores.mean()),
        'std': float(normal_scores.std()),
    }

    os.makedirs(os.path.dirname(SAVE_PATH), exist_ok=True)
    joblib.dump({
        'model': model,
        'scaler': scaler,
        'score_percentiles': score_percentiles
    }, SAVE_PATH)
    print(f"Model saved to: {SAVE_PATH}")

    print(f"\nScore percentiles (on training normal data):")
    for k, v in score_percentiles.items():
        print(f"  {k}: {v:.4f}")

    print(f"\n{'='*60}")
    print("EVALUATION ON KDDTest+ (held-out test set)")
    print(f"{'='*60}")

    test_df = load_and_encode(TEST_PATH)
    X_test = test_df.drop(['label', 'difficulty'], axis=1, errors='ignore').values
    y_test_str = test_df['label'].values

    y_binary = (y_test_str != 'normal').astype(int)
    n_normal = (y_binary == 0).sum()
    n_attack = (y_binary == 1).sum()
    print(f"\nTest set: {len(y_test_str)} samples ({n_normal} normal, {n_attack} attack)")

    X_test_scaled = scaler.transform(X_test)
    raw_scores = -model.score_samples(X_test_scaled)
    norm_scores = np.array([percentile_normalize(s, score_percentiles) for s in raw_scores])

    print(f"Score range: [{norm_scores.min():.4f}, {norm_scores.max():.4f}]")
    print(f"Score mean:  {norm_scores.mean():.4f}, std: {norm_scores.std():.4f}")

    for thresh in [0.3, 0.5, 0.7]:
        is_anomaly = (norm_scores > thresh).astype(int)
        tp = ((is_anomaly == 1) & (y_binary == 1)).sum()
        fp = ((is_anomaly == 1) & (y_binary == 0)).sum()
        tn = ((is_anomaly == 0) & (y_binary == 0)).sum()
        fn = ((is_anomaly == 0) & (y_binary == 1)).sum()

        detection_rate = tp / (tp + fn) if (tp + fn) > 0 else 0
        fp_rate = fp / (fp + tn) if (fp + tn) > 0 else 0
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0
        f1 = 2 * precision * detection_rate / (precision + detection_rate) if (precision + detection_rate) > 0 else 0

        print(f"\n--- Threshold: {thresh} ---")
        print(f"  TP={tp}  FP={fp}  TN={tn}  FN={fn}")
        print(f"  Attack detection rate (recall): {detection_rate:.4f} ({detection_rate*100:.2f}%)")
        print(f"  False positive rate:            {fp_rate:.4f} ({fp_rate*100:.2f}%)")
        print(f"  Anomaly precision:              {precision:.4f}")
        print(f"  Anomaly F1:                     {f1:.4f}")

    return model, scaler, score_percentiles


if __name__ == '__main__':
    model, scaler, percentiles = train_isolation_forest()
