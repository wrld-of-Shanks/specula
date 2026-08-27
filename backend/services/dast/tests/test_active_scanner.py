"""
Unit tests for the DAST active scanner.

Targets backend/services/dast/active_scanner.py

External I/O (HTTP requests and MongoDB) is mocked throughout.
"""

import pytest

import active_scanner
from active_scanner import (
    is_authorized,
    require_authorization,
    NotAuthorizedError,
    check_sqli,
    check_xss,
    check_idor,
    discover_endpoints,
    run_active_scan,
    _finding,
)


class FakeResponse:
    def __init__(self, status_code=200, text='', url=''):
        self.status_code = status_code
        self.text = text
        self.url = url


@pytest.fixture(autouse=True)
def no_sleep(monkeypatch):
    """Eliminate the scanner's inter-request sleep() delays to keep tests fast."""
    monkeypatch.setattr(active_scanner.time, 'sleep', lambda _: None)


@pytest.fixture(autouse=True)
def fake_mongo(monkeypatch):
    """Replace the authorized_targets collection with an in-memory stub."""
    class FakeCollection:
        def __init__(self):
            self.records = {}

        def find_one(self, query):
            return self.records.get(query.get('target'))

    collection = FakeCollection()
    monkeypatch.setattr(active_scanner, 'authorized_targets', collection)
    return collection


@pytest.fixture()
def fake_get(monkeypatch):
    """Replace the module's HTTP GET helper with a controllable mock."""
    def _install(handler):
        monkeypatch.setattr(active_scanner, '_get', handler)
    return _install


# ---------------------------------------------------------------------------
# Authorization
# ---------------------------------------------------------------------------

def test_is_authorized_localhost_true():
    assert is_authorized('http://localhost:8080/search')
    assert is_authorized('http://127.0.0.1/app')


def test_is_authorized_external_matching_record(fake_mongo):
    fake_mongo.records['example.com'] = {'target': 'example.com'}
    assert is_authorized('https://example.com/login')


def test_is_authorized_external_unlisted_false(fake_mongo):
    assert not is_authorized('https://unlisted.example.com/')


def test_require_authorization_allows_localhost():
    require_authorization('http://localhost/')
    # does not raise


def test_require_authorization_raises_for_unauthorized(fake_mongo):
    with pytest.raises(NotAuthorizedError):
        require_authorization('https://evil.example.com/')


# ---------------------------------------------------------------------------
# check_sqli
# ---------------------------------------------------------------------------

def test_sqli_detects_error_disclosure(fake_get):
    fake_get(lambda url, params=None: FakeResponse(
        status_code=400,
        text=f'you have an error in your SQL syntax for {params}',
    ))
    findings = check_sqli('http://localhost/', 'http://localhost/search', 'q')
    assert any(f['check_type'] == 'sqli_error_disclosure' for f in findings)


def test_sqli_detects_behavior_change(fake_get):
    fake_get(lambda url, params=None: FakeResponse(
        status_code=200,
        text='x' * (400 if params and list(params.values())[0] != '1' else 50),
    ))
    findings = check_sqli('http://localhost/', 'http://localhost/search', 'q')
    assert any(f['check_type'] == 'sqli_behavior_change' for f in findings)


def test_sqli_returns_empty_when_no_change(fake_get):
    fake_get(lambda url, params=None: FakeResponse(status_code=200, text='stable'))
    findings = check_sqli('http://localhost/', 'http://localhost/search', 'q')
    assert findings == []


def test_sqli_requires_authorization(fake_mongo):
    with pytest.raises(NotAuthorizedError):
        check_sqli('https://evil.example.com/', 'https://evil.example.com/', 'q')


# ---------------------------------------------------------------------------
# check_xss
# ---------------------------------------------------------------------------

def test_xss_returns_finding_when_reflected(fake_get):
    fake_get(lambda url, params=None: FakeResponse(text='<specula_xss_check_9f3a>'))
    findings = check_xss('http://localhost/', 'http://localhost/search', 'q')
    assert len(findings) == 1
    assert findings[0]['check_type'] == 'reflected_xss'
    assert findings[0]['confidence'] == 0.85


def test_xss_returns_empty_when_escaped(fake_get):
    fake_get(lambda url, params=None: FakeResponse(text='hello'))
    findings = check_xss('http://localhost/', 'http://localhost/search', 'q')
    assert findings == []


# ---------------------------------------------------------------------------
# check_idor
# ---------------------------------------------------------------------------

def test_idor_detects_cross_account_access(monkeypatch):
    def fake_requests_get(url, cookies=None, timeout=None):
        assert cookies == {'session': 'B'}
        # Resource served under a redacted/renamed URL that hides the owner id.
        return FakeResponse(status_code=200, url=url.replace('100', 'ref'))

    monkeypatch.setattr(active_scanner.requests, 'get', fake_requests_get)
    findings = check_idor(
        'http://localhost/',
        'http://localhost/account/{id}',
        {'session': 'A'}, {'session': 'B'}, '100', '200',
    )
    assert len(findings) == 1
    assert findings[0]['check_type'] == 'idor'


def test_idor_returns_empty_when_forbidden(monkeypatch):
    def fake_requests_get(url, cookies=None, timeout=None):
        return FakeResponse(status_code=403, url=url)

    monkeypatch.setattr(active_scanner.requests, 'get', fake_requests_get)
    findings = check_idor(
        'http://localhost/',
        'http://localhost/account/{id}',
        {'session': 'A'}, {'session': 'B'}, '100', '200',
    )
    assert findings == []


# ---------------------------------------------------------------------------
# discover_endpoints
# ---------------------------------------------------------------------------

def test_discover_endpoints_finds_exposed_paths(fake_get):
    fake_get(lambda url, params=None: FakeResponse(status_code=200, url=url))
    findings = discover_endpoints('http://localhost')
    assert findings
    assert all(f['check_type'] == 'exposed_path' for f in findings)
    assert all(f['certainty'] == 'confirmed' for f in findings)


def test_discover_endpoints_skips_non_2xx(fake_get):
    fake_get(lambda url, params=None: FakeResponse(status_code=404))
    findings = discover_endpoints('http://localhost')
    assert findings == []


def test_discover_endpoints_handles_request_exceptions(fake_get):
    import requests
    def raise_exc(url, params=None):
        raise requests.ConnectionError('boom')
    fake_get(raise_exc)
    findings = discover_endpoints('http://localhost')
    assert findings == []


# ---------------------------------------------------------------------------
# _finding
# ---------------------------------------------------------------------------

def test_finding_shape():
    f = _finding('x', 'loc', 'p', 0.9, 'what', 'evidence')
    assert f['event_type'] == 'dast'
    assert f['mode'] == 'active'
    assert f['check_type'] == 'x'
    assert f['certainty'] is None
    confirmed = _finding('c', 'l', None, 1.0, 'w', 'e')
    assert confirmed['certainty'] == 'confirmed'


# ---------------------------------------------------------------------------
# run_active_scan (orchestrator)
# ---------------------------------------------------------------------------

def test_run_active_scan_skips_when_unauthorized(fake_mongo):
    result = run_active_scan('https://evil.example.com/', [])
    assert result['skipped_active'] is True
    assert result['findings'] == []


def test_run_active_scan_orchestrates_checks(fake_get, fake_mongo):
    fake_get(lambda url, params=None: FakeResponse(status_code=200, url=url, text='<specula_xss_check_9f3a>'))
    params = [{'endpoint': 'http://localhost/search', 'param': 'q'}]
    result = run_active_scan('http://localhost', params)
    assert result['skipped_active'] is False
    check_types = {f['check_type'] for f in result['findings']}
    assert 'exposed_path' in check_types
    assert 'reflected_xss' in check_types
