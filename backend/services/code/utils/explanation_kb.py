import json
import os


IMPACT_DESCRIPTIONS = {
    'sql_injection': 'an attacker could read, modify, or delete arbitrary data in the database, including other users\' records, and potentially execute administrative operations',
    'xss': 'an attacker could execute arbitrary JavaScript in a victim\'s browser session, stealing session cookies, redirecting users, or defacing the page',
    'hardcoded_credentials': 'anyone with access to the source code or decompiled binary can obtain the credentials and use them to access the protected system',
    'command_injection': 'an attacker could execute arbitrary operating system commands on the server, potentially gaining full control of the host',
    'path_traversal': 'an attacker could access files outside the intended directory, potentially reading sensitive configuration files or overwriting critical system files',
    'insecure_deserialization': 'an attacker could craft a malicious serialized object that executes arbitrary code when deserialized, potentially achieving remote code execution',
    'not_vulnerable': None
}

REMEDIATION_GUIDANCE = {
    'sql_injection': 'Use parameterized queries or an ORM query builder instead of string concatenation. Never interpolate user input directly into SQL strings. Example: use `cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))` instead of `cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")`. Apply principle of least privilege to database accounts.',
    'xss': 'Encode all output data before rendering it in HTML. Use `textContent` instead of `innerHTML` where possible. Implement a Content Security Policy (CSP) header. Sanitize any user-provided HTML with a library like DOMPurify. Use framework-provided auto-escaping.',
    'hardcoded_credentials': 'Move credentials to environment variables (`process.env.SECRET_KEY`) or a secrets manager. Never commit secrets to version control. Implement credential rotation. Use `.env` files excluded by `.gitignore` for local development.',
    'command_injection': 'Use language-level APIs instead of shelling out to the OS. If system commands are necessary, use argument lists rather than string interpolation (e.g., `subprocess.run(["ls", user_dir])` not `os.system(f"ls {user_dir}")`). Validate and allowlist input.',
    'path_traversal': 'Resolve the file path and verify the result is within the intended directory before accessing it. Use `os.path.realpath()` or `path.resolve()` and check the prefix. Validate against an allowlist of permitted directories.',
    'insecure_deserialization': 'Never deserialize untrusted data with pickle, marshal, or similar modules. Use safe formats like JSON. If pickle is absolutely required, restrict the classes that can be deserialized using a custom Unpickler with an allowlist. For YAML, always use `yaml.safe_load()` instead of `yaml.load()`.',
    'not_vulnerable': None
}

DETECTION_SOURCE_DESCRIPTIONS = {
    'codebert_model': 'model-based detection: CodeBERT classifier identified patterns consistent with this vulnerability class in the submitted code',
    'rule_based': 'rule-based detection: static analysis pattern matched a known-vulnerable construct',
    'passive_probe': 'passive observation: server response behavior indicates the vulnerability may be present',
    'active_probe': 'active probe: injected marker or payload produced a behavioral change consistent with the vulnerability',
    'active_probe_with_evidence': 'active probe with evidence: injected payload caused a measurable response difference confirming the behavioral anomaly'
}


def _get_owasp_category(cwe_id):
    owasp_map = {
        'CWE-89': 'A03:2021 - Injection',
        'CWE-79': 'A03:2021 - Injection',
        'CWE-78': 'A03:2021 - Injection',
        'CWE-22': 'A01:2021 - Broken Access Control',
        'CWE-798': 'A07:2021 - Identification and Authentication Failures',
        'CWE-693': 'A05:2021 - Security Misconfiguration',
        'CWE-319': 'A02:2021 - Cryptographic Failures',
        'CWE-1021': 'A05:2021 - Security Misconfiguration',
        'CWE-614': 'A05:2021 - Security Misconfiguration',
        'CWE-942': 'A05:2021 - Security Misconfiguration',
        'CWE-209': 'A04:2021 - Insecure Design',
        'CWE-200': 'A01:2021 - Broken Access Control',
        'CWE-538': 'A01:2021 - Broken Access Control',
        'CWE-601': 'A01:2021 - Broken Access Control',
        'CWE-326': 'A02:2021 - Cryptographic Failures',
        'CWE-295': 'A02:2021 - Cryptographic Failures',
        'CWE-639': 'A01:2021 - Broken Access Control',
        'CWE-287': 'A07:2021 - Identification and Authentication Failures',
        'CWE-502': 'A08:2021 - Software and Data Integrity Failures',
    }
    return owasp_map.get(cwe_id, 'N/A')


def _build_confidence_note(confidence, detection_source):
    if confidence >= 0.90:
        strength = 'high'
        qualifier = 'exact pattern match against known-vulnerable construct'
    elif confidence >= 0.70:
        strength = 'medium'
        qualifier = 'behavior consistent with the issue but not confirmed with full exploitation'
    else:
        strength = 'low'
        qualifier = 'indirect indicators suggest this issue may be present'

    source_desc = DETECTION_SOURCE_DESCRIPTIONS.get(detection_source, 'automated analysis')
    return f'{strength} confidence ({confidence:.0%}): {source_desc} — {qualifier}'


class ExplanationKB:
    def __init__(self):
        self.kb_path = os.path.join(os.path.dirname(__file__), '..', 'data', 'cwe_kb.json')
        self.kb = self._load_kb()

    def _load_kb(self):
        if os.path.exists(self.kb_path):
            with open(self.kb_path, 'r') as f:
                return json.load(f)
        return self._get_default_kb()

    def _get_default_kb(self):
        return {
            'sql_injection': {
                'cwe': 'CWE-89',
                'name': 'SQL Injection',
                'description': 'Improper neutralization of special elements used in an SQL command.',
                'severity': 'high',
                'owasp': 'A03:2021 - Injection',
                'remediation': [
                    'Use parameterized queries or prepared statements',
                    'Use stored procedures',
                    'Validate and sanitize user input',
                    'Apply principle of least privilege'
                ],
                'examples': [
                    'string query = "SELECT * FROM users WHERE id = " + userId;',
                    'db.execute("DELETE FROM orders WHERE id=" + orderId);'
                ],
                'fix_patterns': [
                    'Use ? placeholders for parameters',
                    'Use parameterized query methods',
                    'Validate input against whitelist'
                ]
            },
            'xss': {
                'cwe': 'CWE-79',
                'name': 'Cross-site Scripting (XSS)',
                'description': 'Improper neutralization of input during web page generation.',
                'severity': 'medium',
                'owasp': 'A03:2021 - Injection',
                'remediation': [
                    'Encode output data',
                    'Validate and sanitize input',
                    'Use Content Security Policy (CSP)',
                    'Use HTTPOnly cookies'
                ],
                'examples': [
                    'document.innerHTML = userInput;',
                    'response.send(`<div>${userInput}</div>`);'
                ],
                'fix_patterns': [
                    'Escape HTML entities',
                    'Use textContent instead of innerHTML',
                    'Sanitize with DOMPurify or similar'
                ]
            },
            'hardcoded_credentials': {
                'cwe': 'CWE-798',
                'name': 'Use of Hard-coded Credentials',
                'description': 'Product contains hard-coded credentials such as a password or cryptographic key.',
                'severity': 'critical',
                'owasp': 'A07:2021 - Identification and Authentication Failures',
                'remediation': [
                    'Store credentials in environment variables',
                    'Use a secrets manager',
                    'Use credential vaults',
                    'Implement proper key rotation'
                ],
                'examples': [
                    'const password = "admin123";',
                    'DB_PASSWORD = "secret_pass"'
                ],
                'fix_patterns': [
                    'Move to environment variables',
                    'Use process.env or config files',
                    'Use secret management services'
                ]
            },
            'command_injection': {
                'cwe': 'CWE-78',
                'name': 'OS Command Injection',
                'description': 'Improper neutralization of special elements used in an OS command.',
                'severity': 'critical',
                'owasp': 'A03:2021 - Injection',
                'remediation': [
                    'Avoid calling OS commands directly',
                    'Use language-level APIs instead',
                    'Validate and sanitize input',
                    'Use parameterized APIs'
                ],
                'examples': [
                    'exec("cat " + filename);',
                    'system("ping " + userInput);'
                ],
                'fix_patterns': [
                    'Use subprocess with argument list',
                    'Validate input against whitelist',
                    'Use built-in language functions'
                ]
            },
            'path_traversal': {
                'cwe': 'CWE-22',
                'name': 'Path Traversal',
                'description': 'Improper limitation of a pathname to a restricted directory.',
                'severity': 'high',
                'owasp': 'A01:2021 - Broken Access Control',
                'remediation': [
                    'Validate and normalize file paths',
                    'Use chroot or jail environments',
                    'Implement proper access controls',
                    'Use allowlisting for file access'
                ],
                'examples': [
                    'readFile("/data/" + userPath);',
                    'fs.readFileSync(baseDir + "/" + filename);'
                ],
                'fix_patterns': [
                    'Resolve and validate path is within allowed directory',
                    'Use path.normalize and check prefix',
                    'Implement allowlist for accessible paths'
                ]
            },
            'insecure_deserialization': {
                'cwe': 'CWE-502',
                'name': 'Insecure Deserialization',
                'description': 'Deserializing untrusted data can allow an attacker to execute arbitrary code.',
                'severity': 'critical',
                'owasp': 'A08:2021 - Software and Data Integrity Failures',
                'remediation': [
                    'Never deserialize untrusted data with pickle',
                    'Use safe formats like JSON',
                    'If pickle is required, restrict deserializable classes',
                    'Use yaml.safe_load() instead of yaml.load()'
                ],
                'examples': [
                    'pickle.loads(user_data)',
                    'yaml.load(raw_config)'
                ],
                'fix_patterns': [
                    'Use JSON for serialization',
                    'Use yaml.safe_load()',
                    'Implement restricted unpickler'
                ]
            },
            'not_vulnerable': {
                'cwe': 'N/A',
                'name': 'Not Vulnerable',
                'description': 'No vulnerability detected in the code.',
                'severity': 'info',
                'owasp': 'N/A',
                'remediation': [],
                'examples': [],
                'fix_patterns': []
            }
        }

    def get_explanation(self, vulnerability_type, code_snippet):
        if vulnerability_type not in self.kb:
            vulnerability_type = 'not_vulnerable'

        entry = self.kb[vulnerability_type]

        return {
            'cwe': entry['cwe'],
            'name': entry['name'],
            'description': entry['description'],
            'severity': entry['severity'],
            'owasp': entry['owasp'],
            'remediation': entry['remediation'],
            'code_context': self._extract_code_context(code_snippet, vulnerability_type),
            'fix_suggestions': entry['fix_patterns']
        }

    def build_structured_explanation(self, vulnerability_type, code_snippet,
                                     confidence, detection_source='codebert_model',
                                     file_path=None, line_range=None,
                                     suggested_fix=None):
        if vulnerability_type not in self.kb:
            vulnerability_type = 'not_vulnerable'

        entry = self.kb[vulnerability_type]

        what = self._build_what(vulnerability_type, code_snippet, entry)
        why = IMPACT_DESCRIPTIONS.get(vulnerability_type)
        location = self._build_code_location(file_path, line_range, code_snippet, vulnerability_type)
        reference = {
            'cwe': entry['cwe'],
            'owasp': _get_owasp_category(entry['cwe'])
        }
        remediation = self._build_remediation(vulnerability_type, suggested_fix)
        confidence_note = _build_confidence_note(confidence, detection_source)

        return {
            'what': what,
            'why_it_matters': why,
            'location': location,
            'reference': reference,
            'remediation': remediation,
            'certainty_type': 'inferred',
            'confidence_note': confidence_note
        }

    def _build_what(self, vulnerability_type, code_snippet, entry):
        if vulnerability_type == 'not_vulnerable':
            return 'No vulnerability detected in the submitted code.'

        code_context = self._extract_code_context(code_snippet, vulnerability_type)
        if code_context:
            first_match = code_context[0]
            return (
                f"{entry['name']} ({entry['cwe']}): "
                f"the pattern `{first_match['code'][:120]}` "
                f"(line {first_match['line_number']}) matches a known-vulnerable construct — "
                f"{entry['description'].lower().rstrip('.')}"
            )

        return (
            f"{entry['name']} ({entry['cwe']}): "
            f"{entry['description']} "
            f"The submitted code contains constructs consistent with this vulnerability class."
        )

    def _build_code_location(self, file_path, line_range, code_snippet, vulnerability_type):
        lines = code_snippet.split('\n')
        vulnerable_lines = []

        patterns = {
            'sql_injection': ['SELECT', 'INSERT', 'UPDATE', 'DELETE', 'query', 'execute'],
            'xss': ['innerHTML', 'outerHTML', 'document.write', 'insertAdjacentHTML'],
            'hardcoded_credentials': ['password', 'secret', 'key', 'token', 'api_key'],
            'command_injection': ['exec', 'system', 'popen', 'eval', 'spawn'],
            'path_traversal': ['readFile', 'writeFile', 'open', 'path', 'fs.'],
            'insecure_deserialization': ['pickle', 'marshal', 'yaml.load', 'shelve', 'dill']
        }

        if vulnerability_type in patterns:
            for i, line in enumerate(lines):
                for pattern in patterns[vulnerability_type]:
                    if pattern.lower() in line.lower():
                        vulnerable_lines.append({
                            'line_number': i + 1,
                            'code': line.strip(),
                            'pattern_matched': pattern
                        })

        if file_path and line_range:
            loc = file_path
            if line_range.get('start') and line_range.get('end'):
                loc += f':{line_range["start"]}-{line_range["end"]}'
            elif line_range.get('start'):
                loc += f':{line_range["start"]}'
            return loc

        if vulnerable_lines:
            first = vulnerable_lines[0]
            return f'line {first["line_number"]} — `{first["code"][:80]}`'

        return 'location not determined (chunk-level scan)'

    def _build_remediation(self, vulnerability_type, suggested_fix=None):
        guidance = REMEDIATION_GUIDANCE.get(vulnerability_type)
        result = {
            'guidance': guidance or 'No specific remediation guidance available.',
            'suggested_code_fix': suggested_fix
        }
        return result

    def _extract_code_context(self, code, vulnerability_type):
        lines = code.split('\n')
        vulnerable_lines = []

        patterns = {
            'sql_injection': ['SELECT', 'INSERT', 'UPDATE', 'DELETE', 'query', 'execute'],
            'xss': ['innerHTML', 'outerHTML', 'document.write', 'insertAdjacentHTML'],
            'hardcoded_credentials': ['password', 'secret', 'key', 'token', 'api_key'],
            'command_injection': ['exec', 'system', 'popen', 'eval', 'spawn'],
            'path_traversal': ['readFile', 'writeFile', 'open', 'path', 'fs.'],
            'insecure_deserialization': ['pickle', 'marshal', 'yaml.load', 'shelve', 'dill']
        }

        if vulnerability_type in patterns:
            for i, line in enumerate(lines):
                for pattern in patterns[vulnerability_type]:
                    if pattern.lower() in line.lower():
                        vulnerable_lines.append({
                            'line_number': i + 1,
                            'code': line.strip(),
                            'pattern_matched': pattern
                        })

        return vulnerable_lines

    def save_kb(self):
        os.makedirs(os.path.dirname(self.kb_path), exist_ok=True)
        with open(self.kb_path, 'w') as f:
            json.dump(self.kb, f, indent=2)

    def add_entry(self, vulnerability_type, entry):
        self.kb[vulnerability_type] = entry
        self.save_kb()
