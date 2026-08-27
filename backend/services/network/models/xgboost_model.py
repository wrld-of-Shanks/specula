import os
import numpy as np
import pandas as pd
import xgboost as xgb
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, log_loss
import joblib

class XGBoostClassifier:
    def __init__(self):
        self.model = None
        self.label_encoder = None
        self.is_trained = False
        
    def is_loaded(self):
        return self.is_trained
    
    def prepare_data(self, data_path):
        df = pd.read_csv(data_path)
        
        categorical_cols = ['protocol_type', 'service', 'flag']
        for col in categorical_cols:
            if col in df.columns:
                df[col] = pd.Categorical(df[col]).codes
        
        X = df.drop(['label', 'difficulty'], axis=1, errors='ignore')
        y = df['label']
        
        from sklearn.preprocessing import LabelEncoder
        self.label_encoder = LabelEncoder()
        y_encoded = self.label_encoder.fit_transform(y)
        
        return X.values, y_encoded
    
    def train(self, data_path, test_size=0.2):
        X, y = self.prepare_data(data_path)
        
        X_train, X_val, y_train, y_val = train_test_split(
            X, y, test_size=test_size, random_state=42, stratify=y
        )
        
        n_classes = len(np.unique(y))
        class_counts = np.bincount(y_train)
        total = len(y_train)
        scale_pos_weight = total / (n_classes * class_counts)
        
        self.model = xgb.XGBClassifier(
            objective='multi:softprob',
            num_class=n_classes,
            max_depth=5,
            learning_rate=0.1,
            n_estimators=200,
            scale_pos_weight=scale_pos_weight.tolist(),
            eval_metric='mlogloss',
            early_stopping_rounds=20,
            random_state=42,
            use_label_encoder=False
        )
        
        self.model.fit(
            X_train, y_train,
            eval_set=[(X_val, y_val)],
            verbose=False
        )
        
        y_pred = self.model.predict(X_val)
        y_pred_proba = self.model.predict_proba(X_val)
        
        print("\n=== XGBoost Evaluation ===")
        print(classification_report(
            y_val, y_pred, 
            target_names=self.label_encoder.classes_
        ))
        print(f"Log Loss: {log_loss(y_val, y_pred_proba):.4f}")
        
        self.is_trained = True
        self.save_model()
        
        return {
            'report': classification_report(
                y_val, y_pred, 
                target_names=self.label_encoder.classes_,
                output_dict=True
            ),
            'log_loss': log_loss(y_val, y_pred_proba)
        }
    
    def predict(self, features):
        if not self.is_trained:
            raise ValueError("Model not trained yet")
        
        features_array = np.array(features).reshape(1, -1)
        
        prediction = self.model.predict(features_array)[0]
        probabilities = self.model.predict_proba(features_array)[0]
        
        predicted_class = self.label_encoder.inverse_transform([prediction])[0]
        confidence = float(probabilities[prediction])
        
        return {
            'class': predicted_class,
            'confidence': confidence,
            'probabilities': {
                self.label_encoder.classes_[i]: float(p) 
                for i, p in enumerate(probabilities)
            }
        }
    
    def save_model(self, path=None):
        if path is None:
            path = os.path.join(os.path.dirname(__file__), 'weights', 'xgboost_model.pkl')
        os.makedirs(os.path.dirname(path), exist_ok=True)
        joblib.dump({
            'model': self.model,
            'label_encoder': self.label_encoder
        }, path)
    
    def load_model(self, path=None):
        if path is None:
            path = os.path.join(os.path.dirname(__file__), 'weights', 'xgboost_model.pkl')
        if os.path.exists(path):
            data = joblib.load(path)
            self.model = data['model']
            self.label_encoder = data['label_encoder']
            self.is_trained = True
            return True
        return False
