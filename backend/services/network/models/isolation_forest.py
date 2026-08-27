import os
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import joblib

class IsolationForestDetector:
    def __init__(self):
        self.model = None
        self.scaler = None
        self.is_trained = False
        
    def is_loaded(self):
        return self.is_trained
    
    def prepare_normal_data(self, data_path):
        df = pd.read_csv(data_path)
        
        categorical_cols = ['protocol_type', 'service', 'flag']
        for col in categorical_cols:
            if col in df.columns:
                df[col] = pd.Categorical(df[col]).codes
        
        normal_mask = df['label'] == 'normal'
        X_normal = df[normal_mask].drop(['label', 'difficulty'], axis=1, errors='ignore')
        
        return X_normal.values
    
    def train(self, data_path, contamination=0.1):
        X_normal = self.prepare_normal_data(data_path)
        
        self.scaler = StandardScaler()
        X_scaled = self.scaler.fit_transform(X_normal)
        
        self.model = IsolationForest(
            contamination=contamination,
            n_estimators=200,
            max_samples='auto',
            random_state=42,
            n_jobs=-1
        )
        
        self.model.fit(X_scaled)
        
        normal_scores = -self.model.score_samples(X_scaled)
        self.score_percentiles = {
            'p50': float(np.percentile(normal_scores, 50)),
            'p75': float(np.percentile(normal_scores, 75)),
            'p90': float(np.percentile(normal_scores, 90)),
            'p95': float(np.percentile(normal_scores, 95)),
            'p99': float(np.percentile(normal_scores, 99)),
            'mean': float(normal_scores.mean()),
            'std': float(normal_scores.std()),
        }
        
        self.is_trained = True
        self.save_model()
        
        return {
            'status': 'trained',
            'samples': len(X_normal),
            'score_percentiles': self.score_percentiles
        }
    
    def predict(self, features):
        if not self.is_trained:
            raise ValueError("Model not trained yet")
        
        features_array = np.array(features).reshape(1, -1)
        features_scaled = self.scaler.transform(features_array)
        
        prediction = self.model.predict(features_scaled)[0]
        raw_score = float(-self.model.score_samples(features_scaled)[0])
        
        normalized_score = self._normalize_score(raw_score)
        
        return {
            'is_anomaly': bool(prediction == -1),
            'anomaly_score': float(normalized_score),
            'raw_score': float(raw_score)
        }
    
    def _normalize_score(self, raw_score):
        if not hasattr(self, 'score_percentiles') or self.score_percentiles is None:
            return float(np.clip(raw_score, 0, 1))
        
        p50 = self.score_percentiles['p50']
        p95 = self.score_percentiles['p95']
        p99 = self.score_percentiles['p99']
        
        if raw_score <= p50:
            return 0.0
        elif raw_score <= p95:
            return 0.3 + 0.4 * (raw_score - p50) / (p95 - p50)
        elif raw_score <= p99:
            return 0.7 + 0.2 * (raw_score - p95) / (p99 - p95)
        else:
            return min(0.9 + 0.1 * (raw_score - p99) / (p99 * 0.5 + 1e-10), 1.0)
    
    def get_confidence(self, anomaly_score):
        if anomaly_score > 0.9:
            return 'high'
        elif anomaly_score > 0.7:
            return 'medium'
        elif anomaly_score > 0.5:
            return 'low'
        return 'none'
    
    def save_model(self, path=None):
        if path is None:
            path = os.path.join(os.path.dirname(__file__), 'weights', 'isolation_forest.pkl')
        os.makedirs(os.path.dirname(path), exist_ok=True)
        joblib.dump({
            'model': self.model,
            'scaler': self.scaler,
            'score_percentiles': self.score_percentiles
        }, path)
    
    def load_model(self, path=None):
        if path is None:
            path = os.path.join(os.path.dirname(__file__), 'weights', 'isolation_forest.pkl')
        if os.path.exists(path):
            data = joblib.load(path)
            self.model = data['model']
            self.scaler = data['scaler']
            self.score_percentiles = data.get('score_percentiles', None)
            self.is_trained = True
            return True
        return False
