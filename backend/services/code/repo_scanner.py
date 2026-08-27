"""
Repo scanner — clones a repo, scans every source file, streams findings.
Runs in a background thread so the HTTP response returns immediately.
"""
import os
import re
import json
import tempfile
import threading
import subprocess
import time
import requests
from urllib.parse import urlparse

SOURCE_EXTENSIONS = {
    '.js', '.ts', '.jsx', '.tsx', '.py', '.java', '.go', '.rs',
    '.c', '.cpp', '.h', '.cs', '.rb', '.php', '.swift', '.kt',
    '.scala', '.sh', '.bash', '.sql', '.html', '.css', '.vue', '.svelte'
}

SKIP_DIRS = {
    'node_modules', 'vendor', 'build', 'dist', '.git',
    '__pycache__', '.tox', 'venv', 'env', '.venv',
    'target', 'bin', 'obj', '.next', '.nuxt', '.opencode'
}

MAX_TOTAL_FILES = 500
MAX_FILE_SIZE = 100 * 1024
CLONE_TIMEOUT = 60
CHUNK_SIZE = 400
CHUNK_OVERLAP = 50

_jobs = {}
_jobs_lock = threading.Lock()


def _emit(job_id, event_type, data):
    """Stub — wire to your WebSocket broadcast."""
    pass


def _get_github_token():
    try:
        result = subprocess.run(
            ['security', 'find-generic-password', '-s', 'github.com', '-w'],
            capture_output=True, text=True, timeout=5
        )
        token = result.stdout.strip()
        if token:
            return f'oauth2:{token}'
    except Exception:
        pass
    env_token = os.environ.get('GITHUB_TOKEN', '')
    if env_token:
        return f'oauth2:{env_token}'
    return 'x-access-token:'


def _clone_with_timeout(repo_url, dest_dir):
    parsed = urlparse(repo_url)
    token = _get_github_token()
    auth_url = f'{parsed.scheme}://{token}@{parsed.netloc}{parsed.path}'

    try:
        result = subprocess.run(
            ['git', 'clone', '--depth', '1', '--single-branch', auth_url, dest_dir],
            capture_output=True, text=True, timeout=CLONE_TIMEOUT
        )
        if result.returncode != 0:
            stderr = result.stderr.strip()
            if 'not found' in stderr.lower() or '404' in stderr:
                return False, 'Repository not found — check the URL'
            if 'Authentication' in stderr or 'credential' in stderr.lower():
                return False, 'Authentication failed — repo may be private'
            return False, f'Clone failed: {stderr[:200]}'
        return True, 'ok'
    except subprocess.TimeoutExpired:
        return False, f'Clone timed out after {CLONE_TIMEOUT}s — repo may be too large or unreachable'
    except Exception as e:
        return False, f'Clone failed: {str(e)[:200]}'


def _should_include_file(filepath):
    ext = os.path.splitext(filepath)[1].lower()
    parts = filepath.split(os.sep)
    return ext in SOURCE_EXTENSIONS and not any(p in SKIP_DIRS for p in parts)


def _collect_source_files(directory):
    files = []
    for root, dirs, filenames in os.walk(directory):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for fname in filenames:
            fpath = os.path.join(root, fname)
            try:
                if os.path.getsize(fpath) <= MAX_FILE_SIZE and _should_include_file(fpath):
                    files.append(fpath)
            except OSError:
                continue
            if len(files) >= MAX_TOTAL_FILES:
                return files
    return files


def _chunk_code(code, chunk_size=CHUNK_SIZE, overlap=CHUNK_OVERLAP):
    lines = code.split('\n')
    chunks = []
    i = 0
    while i < len(lines):
        end = min(i + chunk_size, len(lines))
        chunks.append({
            'code': '\n'.join(lines[i:end]),
            'line_start': i + 1,
            'line_end': end
        })
        if end == len(lines):
            break
        i += chunk_size - overlap
    return chunks


def _scan_file(fpath, tmp_dir, code_service_url, job_id):
    """Scan a single file, return list of findings."""
    relative = os.path.relpath(fpath, tmp_dir)
    try:
        with open(fpath, 'r', errors='replace') as f:
            code = f.read()
    except Exception:
        return []

    if not code.strip():
        return []

    chunks = _chunk_code(code)
    findings = []

    for chunk in chunks:
        try:
            resp = requests.post(
                f'{code_service_url}/scan',
                json={'code': chunk['code']},
                timeout=60
            )
            if resp.status_code != 200:
                continue

            result = resp.json()
            if result.get('prediction') == 'not_vulnerable':
                continue

            loc = result.get('explanation', {}).get('location', '')
            file_location = f"{relative} — {loc}" if loc else f"{relative}:{chunk['line_start']}-{chunk['line_end']}"

            finding = {
                'prediction': result['prediction'],
                'confidence': result['confidence'],
                'cwe': result.get('top_predictions', [{}])[0].get('cwe', 'N/A'),
                'explanation': result.get('explanation', {}),
                'suggested_fix': result.get('suggested_fix'),
                'file_path': relative,
                'line_range': {'start': chunk['line_start'], 'end': chunk['line_end']},
                'location': file_location,
                'top_predictions': result.get('top_predictions', [])
            }
            finding['explanation']['location'] = file_location
            findings.append(finding)

            _emit(job_id, 'finding', finding)

        except Exception:
            continue

    return findings


def _run_scan(job_id, repo_url, code_service_url):
    """Background thread: clone → scan → update job."""
    job = _jobs[job_id]
    tmp_dir = tempfile.mkdtemp(prefix='sentinel-sast-')

    try:
        job['status'] = 'cloning'
        _emit(job_id, 'status', {'status': 'cloning'})

        ok, msg = _clone_with_timeout(repo_url, tmp_dir)
        if not ok:
            job['status'] = 'failed'
            job['error'] = msg
            job['completed_at'] = time.time()
            _emit(job_id, 'failed', {'error': msg})
            return

        job['status'] = 'scanning'
        _emit(job_id, 'status', {'status': 'scanning'})

        source_files = _collect_source_files(tmp_dir)
        job['file_count'] = len(source_files)
        _emit(job_id, 'status', {'status': 'scanning', 'file_count': len(source_files)})

        all_findings = []
        for i, fpath in enumerate(source_files):
            job['files_scanned'] = i + 1
            findings = _scan_file(fpath, tmp_dir, code_service_url, job_id)
            all_findings.extend(findings)

            if findings:
                _emit(job_id, 'progress', {
                    'files_scanned': i + 1,
                    'total_files': len(source_files),
                    'new_findings': len(findings)
                })

        job['findings'] = all_findings
        job['finding_count'] = len(all_findings)
        job['status'] = 'completed'
        job['completed_at'] = time.time()
        _emit(job_id, 'completed', {
            'finding_count': len(all_findings),
            'file_count': len(source_files)
        })

    except Exception as e:
        job['status'] = 'failed'
        job['error'] = str(e)[:500]
        job['completed_at'] = time.time()
        _emit(job_id, 'failed', {'error': str(e)[:500]})
    finally:
        try:
            import shutil
            shutil.rmtree(tmp_dir, ignore_errors=True)
        except Exception:
            pass


def start_repo_scan(repo_url, code_service_url='http://localhost:5002'):
    """Start a background repo scan. Returns (job_id, status_code)."""
    job_id = f'repo-{int(time.time() * 1000)}'
    job = {
        '_id': job_id,
        'repo_url': repo_url,
        'status': 'cloning',
        'file_count': 0,
        'files_scanned': 0,
        'finding_count': 0,
        'findings': [],
        'error': None,
        'started_at': time.time(),
        'completed_at': None
    }

    with _jobs_lock:
        _jobs[job_id] = job

    thread = threading.Thread(target=_run_scan, args=(job_id, repo_url, code_service_url), daemon=True)
    thread.start()

    return job_id


def get_repo_scan(job_id):
    """Get current state of a repo scan job."""
    with _jobs_lock:
        job = _jobs.get(job_id)
    if not job:
        return None

    by_file = {}
    for f in job.get('findings', []):
        fp = f.get('file_path', 'unknown')
        if fp not in by_file:
            by_file[fp] = []
        by_file[fp].append(f)

    return {
        '_id': job['_id'],
        'repo_url': job['repo_url'],
        'status': job['status'],
        'file_count': job.get('file_count', 0),
        'files_scanned': job.get('files_scanned', 0),
        'finding_count': job.get('finding_count', 0),
        'error': job.get('error'),
        'started_at': job.get('started_at'),
        'completed_at': job.get('completed_at'),
        'findings': by_file
    }


def get_all_repo_scans():
    """Get summary of all repo scan jobs."""
    with _jobs_lock:
        jobs = list(_jobs.values())
    return [
        {
            '_id': j['_id'],
            'repo_url': j['repo_url'],
            'status': j['status'],
            'file_count': j.get('file_count', 0),
            'files_scanned': j.get('files_scanned', 0),
            'finding_count': j.get('finding_count', 0),
            'error': j.get('error'),
            'started_at': j.get('started_at'),
            'completed_at': j.get('completed_at'),
        }
        for j in sorted(jobs, key=lambda x: x.get('started_at', 0), reverse=True)
    ]
