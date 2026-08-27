import os
import logging
import numpy as np
import pandas as pd
from flask import Flask, request, jsonify
from flask_cors import CORS
from models.xgboost_model import XGBoostClassifier
from models.isolation_forest import IsolationForestDetector
from models.tpot_model import TPOTClassifier as TPOTWrapper
from utils.feature_engineering import preprocess_flow

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger('horus-nids')

app = Flask(__name__)
CORS(app)

MODELS_DIR = os.path.join(os.path.dirname(__file__), 'models', 'weights')

xgboost_model = XGBoostClassifier()
isolation_forest = IsolationForestDetector()
tpot_model = TPOTWrapper()


def load_models():
    loaded = {}

    tpot_path = os.path.join(MODELS_DIR, 'tpot_pipeline.pkl')
    if os.path.exists(tpot_path):
        if tpot_model.load_model(tpot_path):
            loaded['tpot'] = True
            logger.info("TPOT pipeline loaded from %s", tpot_path)
        else:
            loaded['tpot'] = False
            logger.warning("TPOT pipeline file exists but failed to load")
    else:
        loaded['tpot'] = False
        logger.info("No TPOT pipeline found at %s (run optimize_with_tpot.py to create one)", tpot_path)

    xgb_path = os.path.join(MODELS_DIR, 'xgboost_model.pkl')
    if os.path.exists(xgb_path):
        if xgboost_model.load_model(xgb_path):
            loaded['xgboost'] = True
            logger.info("XGBoost model loaded from %s", xgb_path)
        else:
            loaded['xgboost'] = False
    else:
        loaded['xgboost'] = False
        logger.info("No XGBoost model found at %s", xgb_path)

    if_path = os.path.join(MODELS_DIR, 'isolation_forest.pkl')
    if os.path.exists(if_path):
        if isolation_forest.load_model(if_path):
            loaded['isolation_forest'] = True
            logger.info("Isolation Forest loaded from %s", if_path)
        else:
            loaded['isolation_forest'] = False
    else:
        loaded['isolation_forest'] = False
        logger.info("No Isolation Forest model found at %s", if_path)

    return loaded


@app.before_request
def ensure_models_loaded():
    if not (tpot_model.is_loaded() or xgboost_model.is_loaded()):
        load_models()


@app.route('/health', methods=['GET'])
def health():
    return jsonify({
        'status': 'healthy',
        'models': {
            'tpot': tpot_model.is_loaded(),
            'xgboost': xgboost_model.is_loaded(),
            'isolation_forest': isolation_forest.is_loaded(),
        },
        'active_classifier': 'tpot' if tpot_model.is_loaded() else 'xgboost',
    })


@app.route('/predict', methods=['POST'])
def predict():
    try:
        data = request.get_json()
        features = preprocess_flow(data)

        if tpot_model.is_loaded():
            supervised_result = tpot_model.predict(features)
            supervised_result['model_used'] = 'tpot'
        elif xgboost_model.is_loaded():
            supervised_result = xgboost_model.predict(features)
            supervised_result['model_used'] = 'xgboost'
        else:
            return jsonify({'error': 'No classifier model loaded'}), 503

        unsupervised_result = {'is_anomaly': False, 'anomaly_score': 0.0, 'raw_score': 0.0}
        if isolation_forest.is_loaded():
            unsupervised_result = isolation_forest.predict(features)

        confidence = calculate_confidence(
            supervised_result['confidence'],
            unsupervised_result['anomaly_score']
        )

        prediction = supervised_result['class']
        if unsupervised_result['is_anomaly'] and unsupervised_result['anomaly_score'] > 0.7:
            prediction = 'novel_attack'

        return jsonify({
            'prediction': prediction,
            'confidence': confidence,
            'anomaly_score': unsupervised_result['anomaly_score'],
            'supervised': supervised_result,
            'unsupervised': unsupervised_result,
            'explanation': generate_explanation(prediction, confidence, unsupervised_result)
        })
    except Exception as e:
        logger.exception("Prediction failed")
        return jsonify({'error': str(e)}), 500


@app.route('/train', methods=['POST'])
def train():
    try:
        data_path = request.json.get('data_path', 'data/nsl-kdd.csv')

        xgboost_model.train(data_path)
        isolation_forest.train(data_path)

        return jsonify({'status': 'training_complete'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/models/info', methods=['GET'])
def models_info():
    info = {
        'tpot': tpot_model.get_info(),
        'xgboost': {
            'loaded': xgboost_model.is_loaded(),
            'type': 'xgboost',
        },
        'isolation_forest': {
            'loaded': isolation_forest.is_loaded(),
            'type': 'isolation_forest',
        },
        'active_classifier': 'tpot' if tpot_model.is_loaded() else 'xgboost',
    }
    return jsonify(info)


def calculate_confidence(supervised_conf, anomaly_score):
    if anomaly_score > 0.9:
        return max(supervised_conf, 0.85)
    elif anomaly_score > 0.7:
        return max(supervised_conf, 0.7)
    elif anomaly_score > 0.5:
        return supervised_conf * 0.9
    return supervised_conf


def generate_explanation(prediction, confidence, unsupervised_result):
    is_novel = unsupervised_result['is_anomaly'] and unsupervised_result['anomaly_score'] > 0.7
    return {
        'prediction': prediction,
        'confidence': confidence,
        'is_novel': is_novel,
        'anomaly_score': unsupervised_result['anomaly_score'],
        'override_reason': 'unsupervised_anomaly' if is_novel else None
    }


if __name__ == '__main__':
    load_models()
    app.run(host='0.0.0.0', port=5001, debug=False)
