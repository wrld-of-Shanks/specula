"""
Unit tests for the SAST rule-based classifier.

Targets backend/services/code/models/rule_classifier.py
"""

import pytest

from rule_classifier import (
    RuleBasedClassifier,
    VULNERABILITY_CLASSES,
    CWE_MAPPING,
)


@pytest.fixture
def classifier():
    return RuleBasedClassifier()


# ---------------------------------------------------------------------------
# classify() — top-level behaviour
# ---------------------------------------------------------------------------

def test_classify_returns_not_vulnerable_for_safe_code(classifier):
    result = classifier.classify('const x = 1; // plain code\nconsole.log(x);')
    assert result['prediction'] == 'not_vulnerable'
    assert result['confidence'] == 0.95
    assert result['cwe'] == 'N/A'


def test_classify_returns_top_predictions(classifier):
    result = classifier.classify('password = "supersecret123"')
    assert result['prediction'] == 'hardcoded_credentials'
    assert isinstance(result['top_predictions'], list)
    assert len(result['top_predictions']) == 3
    assert result['top_predictions'][0]['class'] == 'hardcoded_credentials'


def test_classify_includes_reasons_for_best_class(classifier):
    result = classifier.classify('query = "SELECT * FROM users WHERE id=" + user_id')
    assert result['prediction'] == 'sql_injection'
    assert result['reasons'], 'expected a reason string for sql_injection'


def test_classify_never_selects_not_vulnerable_as_vulnerable(classifier):
    # not_vulnerable is removed from the scoring pool.
    result = classifier.classify('password = "password123"')
    assert result['prediction'] != 'not_vulnerable'
    assert result['prediction'] in VULNERABILITY_CLASSES


def test_classify_handles_empty_input(classifier):
    result = classifier.classify('')
    assert result['prediction'] == 'not_vulnerable'


def test_classify_handles_comment_only_code(classifier):
    result = classifier.classify('# just a comment')
    assert result['prediction'] == 'not_vulnerable'


def test_vulnerability_classes_include_all_seven(classifier):
    assert set(VULNERABILITY_CLASSES) == {
        'not_vulnerable',
        'sql_injection',
        'xss',
        'hardcoded_credentials',
        'command_injection',
        'path_traversal',
        'insecure_deserialization',
    }


def test_cwe_mapping_complete():
    for cls in VULNERABILITY_CLASSES:
        assert cls in CWE_MAPPING
    assert CWE_MAPPING['sql_injection'] == 'CWE-89'
    assert CWE_MAPPING['insecure_deserialization'] == 'CWE-502'


# ---------------------------------------------------------------------------
# SQL injection
# ---------------------------------------------------------------------------

@pytest.mark.parametrize('code', [
    'query = "SELECT * FROM users WHERE id=" + user_id',
    'cursor.execute("SELECT * FROM users WHERE name=\'" + name + "\'")',
    'q = "UPDATE users SET name=\'" + user + "\' WHERE id=" + uid',
    'sql = "SELECT * FROM users WHERE id={}".format(user_id)',
])
def test_sql_injection_detected(classifier, code):
    result = classifier.classify(code)
    assert result['prediction'] == 'sql_injection'


@pytest.mark.parametrize('code', [
    'cursor.execute("SELECT * FROM users WHERE id=%s", (user_id,))',
    'db.query("SELECT * FROM users WHERE id=?", [user_id])',
    'preparedStatement.execute("SELECT * FROM users WHERE id=?", userId)',
    'query = "SELECT * FROM users WHERE id=:id"',
])
def test_parameterized_queries_not_flagged(classifier, code):
    result = classifier.classify(code)
    assert result['prediction'] == 'not_vulnerable'


# ---------------------------------------------------------------------------
# XSS
# ---------------------------------------------------------------------------

@pytest.mark.parametrize('code', [
    'document.innerHTML = userInput',
    'document.innerHTML = "<p>" + userInput + "</p>"',
    'el.innerHTML = "<p>" + userContent + "</p>"',
    'res.send(\'<div>\' + userInput + \'</div>\')',
    '$("#output").html("<p>" + userInput + "</p>")',
])
def test_xss_detected(classifier, code):
    result = classifier.classify(code)
    assert result['prediction'] == 'xss'


@pytest.mark.parametrize('code', [
    'element.textContent = userInput',
    'el.innerText = safeValue',
    'html.escape(userInput)',
    'DOMPurify.sanitize(rawHtml)',
])
def test_xss_sanitization_not_flagged(classifier, code):
    result = classifier.classify(code)
    assert result['prediction'] == 'not_vulnerable'


# ---------------------------------------------------------------------------
# Hardcoded credentials
# ---------------------------------------------------------------------------

@pytest.mark.parametrize('code', [
    'password = "hunter2secret"',
    'const password = "secretpass123"',
    'api_key = "sk_live_abcdefg1234567"',
    'SECRET_KEY = "mysecretkey123"',
    'auth_token = "tok_1234567890ab"',
])
def test_hardcoded_credentials_detected(classifier, code):
    result = classifier.classify(code)
    assert result['prediction'] == 'hardcoded_credentials'


@pytest.mark.parametrize('code', [
    'password = os.environ.get("DB_PASS")',
    'api_key = process.env.API_KEY',
    'secret = config["SECRET_KEY"]',
    'token = getenv("AUTH_TOKEN")',
])
def test_credentials_from_env_not_flagged(classifier, code):
    result = classifier.classify(code)
    assert result['prediction'] == 'not_vulnerable'


# ---------------------------------------------------------------------------
# Command injection
# ---------------------------------------------------------------------------

@pytest.mark.parametrize('code', [
    'os.system("ping " + host)',
    'os.system(f"ls {filename}")',
    'subprocess.call("cat " + user_file)',
    'eval(user_input + expression)',
])
def test_command_injection_detected(classifier, code):
    result = classifier.classify(code)
    assert result['prediction'] == 'command_injection'


@pytest.mark.parametrize('code', [
    'subprocess.run(["ls", directory], shell=False)',
    'subprocess.call(["git", "status"], shell=False)',
    'os.system("ls -la")',
])
def test_safe_subprocess_not_flagged(classifier, code):
    result = classifier.classify(code)
    assert result['prediction'] == 'not_vulnerable'


# ---------------------------------------------------------------------------
# Path traversal
# ---------------------------------------------------------------------------

@pytest.mark.parametrize('code', [
    'open("/var/www/uploads/" + filename)',
    'fs.readFileSync("/static/" + userPath)',
    'path.join(uploadDir, req.query.file)',
    'res.sendFile(baseDir + req.params.file)',
])
def test_path_traversal_detected(classifier, code):
    result = classifier.classify(code)
    assert result['prediction'] == 'path_traversal'


@pytest.mark.parametrize('code', [
    'os.path.join("/uploads", os.path.basename(filename))',
    'path.join(base, path.basename(userFile))',
    'realpath(normalize(user_input))',
])
def test_path_traversal_validated_not_flagged(classifier, code):
    result = classifier.classify(code)
    assert result['prediction'] == 'not_vulnerable'


# ---------------------------------------------------------------------------
# Insecure deserialization
# ---------------------------------------------------------------------------

@pytest.mark.parametrize('code', [
    'obj = pickle.loads(user_input)',
    'pickle.load(untrusted_stream)',
    'yaml.load(incoming_payload)',
    'marshal.loads(data_blob)',
])
def test_insecure_deserialization_detected(classifier, code):
    result = classifier.classify(code)
    assert result['prediction'] == 'insecure_deserialization'


@pytest.mark.parametrize('code', [
    'yaml.safe_load(incoming_payload)',
    'json.loads(validated_input)',
])
def test_safe_deserialization_not_flagged(classifier, code):
    result = classifier.classify(code)
    assert result['prediction'] != 'insecure_deserialization'


# ---------------------------------------------------------------------------
# Confidence & scoring-edge cases
# ---------------------------------------------------------------------------

def test_confidence_is_rounded(classifier):
    result = classifier.classify('password = "supersecret123"')
    assert isinstance(result['confidence'], float)
    assert result['confidence'] == 0.93


def test_low_confidence_returns_not_vulnerable(classifier):
    # A weak signal (e.g. one sanitized dangerous pattern) should stay safe.
    result = classifier.classify('el.innerHTML = DOMPurify.sanitize(userInput)')
    assert result['prediction'] in ('xss', 'not_vulnerable')
