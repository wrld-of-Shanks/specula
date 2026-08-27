import os
import numpy as np
import joblib


class TPOTClassifier:
    def __init__(self):
        self.pipeline = None
        self.label_encoder = None
        self.is_trained = False
        self.metadata = {}

    def is_loaded(self):
        return self.is_trained

    def load_model(self, path=None):
        if path is None:
            path = os.path.join(os.path.dirname(__file__), 'weights', 'tpot_pipeline.pkl')
        if os.path.exists(path):
            data = joblib.load(path)
            self.pipeline = data['pipeline']
            self.label_encoder = data['label_encoder']
            self.metadata = {
                'accuracy': data.get('accuracy'),
                'macro_f1': data.get('macro_f1'),
                'weighted_f1': data.get('weighted_f1'),
                'best_pipeline_str': data.get('best_pipeline_str', ''),
                'elapsed_seconds': data.get('elapsed_seconds'),
            }
            self.is_trained = True
            return True
        return False

    def predict(self, features):
        if not self.is_trained:
            raise ValueError("TPOT pipeline not loaded")

        features_array = np.array(features).reshape(1, -1)

        prediction = self.pipeline.predict(features_array)[0]

        predicted_class = self.label_encoder.inverse_transform([int(prediction)])[0]

        confidence = 0.0
        if hasattr(self.pipeline, 'predict_proba'):
            try:
                proba = self.pipeline.predict_proba(features_array)[0]
                confidence = float(proba[int(prediction)])
            except Exception:
                confidence = 0.0

        return {
            'class': predicted_class,
            'confidence': confidence,
            'model': 'tpot',
            'pipeline': self.metadata.get('best_pipeline_str', ''),
        }

    def get_info(self):
        return {
            'loaded': self.is_trained,
            'type': 'tpot_automl',
            'pipeline': self.metadata.get('best_pipeline_str', ''),
            'metrics': {
                'accuracy': self.metadata.get('accuracy'),
                'macro_f1': self.metadata.get('macro_f1'),
                'weighted_f1': self.metadata.get('weighted_f1'),
            },
        }
