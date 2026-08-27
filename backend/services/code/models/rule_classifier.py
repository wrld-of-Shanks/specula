import re


VULNERABILITY_CLASSES = [
    'not_vulnerable',
    'sql_injection',
    'xss',
    'hardcoded_credentials',
    'command_injection',
    'path_traversal',
    'insecure_deserialization'
]

CWE_MAPPING = {
    'not_vulnerable': 'N/A',
    'sql_injection': 'CWE-89',
    'xss': 'CWE-79',
    'hardcoded_credentials': 'CWE-798',
    'command_injection': 'CWE-78',
    'path_traversal': 'CWE-22',
    'insecure_deserialization': 'CWE-502'
}


class RuleBasedClassifier:
    def __init__(self):
        self.is_trained = True

    def is_loaded(self):
        return True

    def classify(self, code):
        scores = {cls: 0.0 for cls in VULNERABILITY_CLASSES}
        reasons = {cls: [] for cls in VULNERABILITY_CLASSES}

        self._check_sql_injection(code, scores, reasons)
        self._check_xss(code, scores, reasons)
        self._check_hardcoded_credentials(code, scores, reasons)
        self._check_command_injection(code, scores, reasons)
        self._check_path_traversal(code, scores, reasons)
        self._check_insecure_deserialization(code, scores, reasons)

        del scores['not_vulnerable']

        best_class = max(scores, key=scores.get)
        best_score = scores[best_class]

        if best_score < 0.30:
            return {
                'prediction': 'not_vulnerable',
                'cwe': 'N/A',
                'confidence': 0.95,
                'top_predictions': [{'class': 'not_vulnerable', 'cwe': 'N/A', 'confidence': 0.95}]
            }

        top3 = sorted(scores.items(), key=lambda x: x[1], reverse=True)[:3]
        top_predictions = []
        for cls, score in top3:
            top_predictions.append({
                'class': cls,
                'cwe': CWE_MAPPING[cls],
                'confidence': round(score, 3)
            })

        return {
            'prediction': best_class,
            'cwe': CWE_MAPPING[best_class],
            'confidence': round(best_score, 3),
            'top_predictions': top_predictions,
            'reasons': reasons.get(best_class, [])
        }

    def _check_sql_injection(self, code, scores, reasons):
        lines = code.split('\n')
        has_string_concat_in_query = False
        has_parameterized = False

        sql_keywords = r'\b(SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|CREATE|EXEC|EXECUTE)\b'

        for i, line in enumerate(lines):
            stripped = line.strip()
            if not stripped or stripped.startswith('#') or stripped.startswith('//'):
                continue

            if re.search(sql_keywords, line, re.IGNORECASE):
                if re.search(r'["\'].*%s.*["\'].*%\s*\w', line) or \
                   re.search(r'["\'].*\?.*["\'].*%', line) or \
                   re.search(r'["\'].*:\w+.*["\'].format\(', line) or \
                   re.search(r'\.execute\([^)]*,\s*\(', line):
                    has_parameterized = True
                    continue

                if re.search(r'["\'].*\+\s*\w', line) and re.search(sql_keywords, line, re.IGNORECASE):
                    has_string_concat_in_query = True
                    reasons['sql_injection'].append(
                        f'line {i+1}: string concatenation in SQL query'
                    )

                if re.search(r'f["\'].*{.*}.*(?:SELECT|INSERT|UPDATE|DELETE)', line, re.IGNORECASE):
                    has_string_concat_in_query = True
                    reasons['sql_injection'].append(
                        f'line {i+1}: f-string interpolation in SQL query'
                    )

                if re.search(r'\.format\(.*\).*(?:SELECT|INSERT|UPDATE|DELETE)', line, re.IGNORECASE) or \
                   re.search(r'(?:SELECT|INSERT|UPDATE|DELETE).*\.format\(', line, re.IGNORECASE):
                    has_string_concat_in_query = True
                    reasons['sql_injection'].append(
                        f'line {i+1}: .format() interpolation in SQL query'
                    )

                if re.search(r'["\'].*\+\s*["\'].*(?:SELECT|INSERT|UPDATE|DELETE)', line, re.IGNORECASE) or \
                   re.search(r'(?:SELECT|INSERT|UPDATE|DELETE).*["\'].*\+\s*["\']', line, re.IGNORECASE):
                    has_string_concat_in_query = True
                    reasons['sql_injection'].append(
                        f'line {i+1}: string concatenation across SQL query'
                    )

        if has_string_concat_in_query and not has_parameterized:
            scores['sql_injection'] = 0.92
        elif has_string_concat_in_query and has_parameterized:
            scores['sql_injection'] = 0.35

    def _check_xss(self, code, scores, reasons):
        lines = code.split('\n')
        has_unescaped_output = False
        has_sanitization = False

        dangerous_output_patterns = [
            (r'res\.(send|write)\s*\(`[^`]*\$\{', 'template literal interpolation in HTTP response'),
            (r'res\.(send|write)\s*\([^)]*\+', 'string concatenation in HTTP response'),
            (r'res\.(send|write)\s*\(.*\.format\(', '.format() in HTTP response'),
            (r'document\.innerHTML\s*=', 'innerHTML assignment'),
            (r'document\.writeln\s*\(', 'document.writeln with dynamic content'),
            (r'\.html\s*\([^)]*\+', 'jQuery .html() with concatenation'),
            (r'innerHTML\s*=\s*[^;]*\+', 'innerHTML with string concatenation'),
        ]

        safe_patterns = [
            r'\.textContent\s*=',
            r'escape\(',
            r'encodeURI',
            r'DOMPurify',
            r'htmlEscape',
            r'sanitize',
            r'innerText\s*=',
        ]

        for i, line in enumerate(lines):
            stripped = line.strip()
            if not stripped or stripped.startswith('#') or stripped.startswith('//'):
                continue

            for pattern, desc in dangerous_output_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    has_unescaped_output = True
                    reasons['xss'].append(f'line {i+1}: {desc}')

            for pattern in safe_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    has_sanitization = True

        if has_unescaped_output and not has_sanitization:
            scores['xss'] = 0.90
        elif has_unescaped_output and has_sanitization:
            scores['xss'] = 0.30

    def _check_hardcoded_credentials(self, code, scores, reasons):
        lines = code.split('\n')

        cred_patterns = [
            (r'(?:password|passwd|pwd)\s*=\s*["\'][^"\']{4,}["\']', 'hardcoded password'),
            (r'(?:secret|secret_key|secret_key_id)\s*=\s*["\'][^"\']{8,}["\']', 'hardcoded secret'),
            (r'(?:api_key|apikey|api_key_id)\s*=\s*["\'][^"\']{8,}["\']', 'hardcoded API key'),
            (r'(?:access_key|auth_token|bearer)\s*=\s*["\'][^"\']{8,}["\']', 'hardcoded token'),
            (r'(?:private_key|signing_key)\s*=\s*["\'][^"\']{8,}["\']', 'hardcoded private key'),
            (r'(?:STRIPE_SECRET|AWS_SECRET|GITHUB_TOKEN|SLACK_TOKEN)\s*=\s*["\'][^"\']{8,}["\']',
             'hardcoded service credential'),
            (r'(?:sk_live|sk_test|pk_live|pk_test)_[a-zA-Z0-9]{10,}',
             'Stripe secret key pattern'),
        ]

        safe_patterns = [
            r'os\.environ',
            r'process\.env',
            r'getenv\(',
            r'config\[',
            r'vault\.',
            r'\.get\(["\'].*["\']\s*,',
        ]

        for i, line in enumerate(lines):
            stripped = line.strip()
            if not stripped or stripped.startswith('#') or stripped.startswith('//'):
                continue

            for pattern, desc in cred_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    is_safe = any(re.search(sp, line, re.IGNORECASE) for sp in safe_patterns)
                    if not is_safe:
                        scores['hardcoded_credentials'] = max(scores['hardcoded_credentials'], 0.93)
                        reasons['hardcoded_credentials'].append(f'line {i+1}: {desc}')

    def _check_command_injection(self, code, scores, reasons):
        lines = code.split('\n')
        has_shell_concat = False
        has_safe_api = False

        dangerous_patterns = [
            (r'os\.system\s*\([^)]*\+', 'os.system with string concatenation'),
            (r'os\.system\s*\(\s*f["\']', 'os.system with f-string'),
            (r'os\.system\s*\(\s*["\'].*%\s', 'os.system with % formatting'),
            (r'os\.popen\s*\([^)]*\+', 'os.popen with string concatenation'),
            (r'subprocess\.call\s*\(\s*["\']', 'subprocess.call with shell string'),
            (r'subprocess\.Popen\s*\(\s*["\']', 'subprocess.Popen with shell string'),
            (r'exec\s*\([^)]*\+', 'exec with string concatenation'),
            (r'eval\s*\([^)]*\+', 'eval with string concatenation'),
            (r'system\s*\([^)]*\+', 'system() with string concatenation'),
        ]

        safe_patterns = [
            r'subprocess\.\w+\s*\(\s*\[',
            r'subprocess\.\w+\s*\(\s*\w+\s*,',
            r'os\.system\s*\(\s*["\'][^"\']+["\']\s*\)',
        ]

        for i, line in enumerate(lines):
            stripped = line.strip()
            if not stripped or stripped.startswith('#') or stripped.startswith('//'):
                continue

            for pattern, desc in dangerous_patterns:
                if re.search(pattern, line):
                    has_shell_concat = True
                    reasons['command_injection'].append(f'line {i+1}: {desc}')

            for pattern in safe_patterns:
                if re.search(pattern, line):
                    has_safe_api = True

        if has_shell_concat and not has_safe_api:
            scores['command_injection'] = 0.93
        elif has_shell_concat and has_safe_api:
            scores['command_injection'] = 0.25

    def _check_path_traversal(self, code, scores, reasons):
        lines = code.split('\n')
        has_user_path = False
        has_validation = False

        dangerous_patterns = [
            (r'readFile\s*\([^)]*\+', 'readFile with concatenation'),
            (r'fs\.\w+Sync\s*\([^)]*\+', 'fs sync method with concatenation'),
            (r'open\s*\([^)]*\+', 'open() with concatenation'),
            (r'path\.join\s*\([^)]*req\.', 'path.join with request param'),
            (r'sendFile\s*\([^)]*req\.', 'sendFile with request param'),
            (r'path\.join\s*\([^)]*query', 'path.join with query param'),
            (r'path\.join\s*\([^)]*params', 'path.join with route params'),
        ]

        validation_patterns = [
            r'realpath',
            r'normalize',
            r'\.\./',
            r'allowlist',
            r'whitelist',
            r'validate.*path',
        ]

        for i, line in enumerate(lines):
            stripped = line.strip()
            if not stripped or stripped.startswith('#') or stripped.startswith('//'):
                continue

            for pattern, desc in dangerous_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    has_user_path = True
                    reasons['path_traversal'].append(f'line {i+1}: {desc}')

            for pattern in validation_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    has_validation = True

        if has_user_path and not has_validation:
            scores['path_traversal'] = 0.85
        elif has_user_path and has_validation:
            scores['path_traversal'] = 0.30

    def _check_insecure_deserialization(self, code, scores, reasons):
        lines = code.split('\n')

        dangerous_patterns = [
            (r'pickle\.loads?\s*\(', 'pickle.loads() on untrusted data'),
            (r'pickle\.Unpickler', 'pickle Unpickler'),
            (r'yaml\.load\s*\([^)]*(?!\s*Loader\s*=\s*yaml\.SafeLoader)', 'yaml.load without SafeLoader'),
            (r'marshal\.loads?\s*\(', 'marshal.loads()'),
            (r'shelve\.open\s*\(', 'shelve.open()'),
            (r'dill\.loads?\s*\(', 'dill.loads()'),
        ]

        for i, line in enumerate(lines):
            stripped = line.strip()
            if not stripped or stripped.startswith('#') or stripped.startswith('//'):
                continue

            for pattern, desc in dangerous_patterns:
                if re.search(pattern, line):
                    if 'yaml' in pattern:
                        if not re.search(r'yaml\.safe_load', line):
                            scores['insecure_deserialization'] = 0.92
                            reasons['insecure_deserialization'].append(f'line {i+1}: {desc}')
                    else:
                        scores['insecure_deserialization'] = 0.92
                        reasons['insecure_deserialization'].append(f'line {i+1}: {desc}')
