import os
from flask import Flask, request, jsonify
from flask_cors import CORS
from models.codebert_classifier import CodeBERTClassifier
from models.codet5_fixer import CodeT5Fixer
from utils.explanation_kb import ExplanationKB
from repo_scanner import start_repo_scan, get_repo_scan, get_all_repo_scans

app = Flask(__name__)
CORS(app, origins=['http://localhost:3000', 'http://gateway:3000'])

MODELS_DIR = os.path.join(os.path.dirname(__file__), 'models', 'weights')

classifier = CodeBERTClassifier()
fixer = CodeT5Fixer()
explanation_kb = ExplanationKB()


@app.route('/health', methods=['GET'])
def health():
    return jsonify({
        'status': 'healthy',
        'models': {
            'classifier': classifier.is_loaded(),
            'fixer': fixer.is_loaded()
        }
    })


@app.route('/scan', methods=['POST'])
def scan():
    try:
        data = request.get_json()
        code = data.get('code', '')

        if not code:
            return jsonify({'error': 'No code provided'}), 400

        classification = classifier.classify(code)

        detection_source = 'rule_based'
        if classifier.is_loaded():
            detection_source = 'codebert_model'

        suggested_fix = None
        fix_confidence = None
        if classification['prediction'] != 'not_vulnerable':
            fix_result = fixer.generate_fix(code, classification['prediction'])
            suggested_fix = fix_result.get('fix')
            fix_confidence = fix_result.get('confidence')

        explanation = explanation_kb.build_structured_explanation(
            vulnerability_type=classification['prediction'],
            code_snippet=code,
            confidence=classification['confidence'],
            detection_source=detection_source,
            suggested_fix=suggested_fix
        )

        return jsonify({
            'prediction': classification['prediction'],
            'confidence': classification['confidence'],
            'top_predictions': classification['top_predictions'],
            'explanation': explanation,
            'suggested_fix': suggested_fix,
            'fix_confidence': fix_confidence
        })
    except Exception as e:
        app.logger.error(f"Scan failed: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500


@app.route('/fix', methods=['POST'])
def fix():
    try:
        data = request.get_json()
        code = data.get('code', '')
        vulnerability_type = data.get('type', '')

        if not code:
            return jsonify({'error': 'No code provided'}), 400

        fix_result = fixer.generate_fix(code, vulnerability_type)

        return jsonify({
            'fix': fix_result.get('fix'),
            'confidence': fix_result.get('confidence'),
            'original_code': code
        })
    except Exception as e:
        app.logger.error(f"Fix generation failed: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500


@app.route('/train', methods=['POST'])
def train():
    try:
        data = request.json
        model_type = data.get('model_type', 'classifier')

        if model_type == 'classifier':
            data_path = data.get('data_path', 'data/cve_dataset.csv')
            result = classifier.train(data_path)
        elif model_type == 'fixer':
            data_path = data.get('data_path', 'data/fixes_dataset.csv')
            result = fixer.train(data_path)
        else:
            return jsonify({'error': 'Invalid model type'}), 400

        return jsonify({'status': 'training_complete', 'result': result})
    except Exception as e:
        app.logger.error(f"Training failed: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500


@app.route('/repo-scan', methods=['GET'])
def repo_scan_list():
    try:
        jobs = get_all_repo_scans()
        return jsonify(jobs)
    except Exception as e:
        app.logger.error(f"Failed to list scan jobs: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500


@app.route('/repo-scan', methods=['POST'])
def repo_scan_start():
    try:
        data = request.get_json()
        repo_url = data.get('repo_url', '')
        if not repo_url:
            return jsonify({'error': 'repo_url is required'}), 400

        code_service_url = os.environ.get('CODE_SERVICE_URL', 'http://localhost:5002')
        job_id = start_repo_scan(repo_url, code_service_url)
        return jsonify({'job_id': job_id, 'status': 'cloning'}), 202
    except Exception as e:
        app.logger.error(f"Failed to start repo scan: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500


@app.route('/repo-scan/<job_id>', methods=['GET'])
def repo_scan_status(job_id):
    try:
        result = get_repo_scan(job_id)
        if not result:
            return jsonify({'error': 'Job not found'}), 404
        return jsonify(result)
    except Exception as e:
        app.logger.error(f"Failed to get scan status: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500


@app.errorhandler(Exception)
def handle_exception(e):
    app.logger.error(f"Unhandled exception: {str(e)}")
    return jsonify({'error': 'Internal server error'}), 500


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5002, debug=False)
