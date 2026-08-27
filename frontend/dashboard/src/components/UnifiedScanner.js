import React, { useState, useEffect, useRef, useCallback } from 'react';
import { Search, Code, GitBranch, Globe, AlertTriangle, CheckCircle, Loader, ChevronDown } from 'lucide-react';
import { scanCode, scanRepo, dastScan, getScanJob } from '../services/api';
import FindingCard from './FindingCard';

const detectInputType = (input) => {
  const trimmed = input.trim();
  if (/^https?:\/\/github\.com\//i.test(trimmed) || /^git@github\.com:/i.test(trimmed)) {
    return 'repo';
  }
  if (/^https?:\/\//i.test(trimmed)) {
    return 'dast';
  }
  if (trimmed.length > 0) {
    return 'code';
  }
  return null;
};

const isLocalhost = (url) => {
  try {
    const host = new URL(url.trim()).hostname;
    return ['localhost', '127.0.0.1', '0.0.0.0'].includes(host);
  } catch { return false; }
};

const TYPE_CONFIG = {
  code: { icon: Code, label: 'Code', color: '#3b82f6', hint: 'Paste JavaScript, Python, Java, etc.' },
  repo: { icon: GitBranch, label: 'Repository', color: '#f59e0b', hint: 'GitHub repository URL' },
  dast: { icon: Globe, label: 'Website', color: '#f97316', hint: 'Live website URL to scan' },
};

const UnifiedScanner = ({ onResumeFeed }) => {
  const [input, setInput] = useState('');
  const [detectedType, setDetectedType] = useState(null);
  const [dastMode, setDastMode] = useState('passive');
  const [verboseEvidence, setVerboseEvidence] = useState(false);
  const [result, setResult] = useState(null);
  const [repoResult, setRepoResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [elapsed, setElapsed] = useState(0);
  const repoJobIdRef = useRef(null);
  const pollTimerRef = useRef(null);
  const elapsedTimerRef = useRef(null);
  const startTimeRef = useRef(null);

  const handleInputChange = (e) => {
    const val = e.target.value;
    setInput(val);
    setDetectedType(detectInputType(val));
    if (/^https?:\/\//i.test(val.trim()) && !isLocalhost(val)) {
      setDastMode('active');
    }
    if (result || repoResult || error) {
      setResult(null);
      setRepoResult(null);
      setError(null);
      setElapsed(0);
      if (pollTimerRef.current) clearTimeout(pollTimerRef.current);
      stopElapsedTimer();
    }
  };

  useEffect(() => {
    return () => {
      if (pollTimerRef.current) clearTimeout(pollTimerRef.current);
      if (elapsedTimerRef.current) clearInterval(elapsedTimerRef.current);
    };
  }, []);

  const startElapsedTimer = useCallback(() => {
    startTimeRef.current = Date.now();
    setElapsed(0);
    elapsedTimerRef.current = setInterval(() => {
      setElapsed(Math.floor((Date.now() - startTimeRef.current) / 1000));
    }, 1000);
  }, []);

  const stopElapsedTimer = useCallback(() => {
    if (elapsedTimerRef.current) {
      clearInterval(elapsedTimerRef.current);
      elapsedTimerRef.current = null;
    }
  }, []);

  const formatTime = (secs) => {
    if (secs < 60) return `${secs}s`;
    const m = Math.floor(secs / 60);
    const s = secs % 60;
    return `${m}m ${s}s`;
  };

  const startRepoPolling = useCallback((jobId) => {
    repoJobIdRef.current = jobId;
    startElapsedTimer();

    const poll = async () => {
      try {
        const data = await getScanJob(jobId);
        setRepoResult(prev => ({ ...prev, job_id: jobId, _jobData: data }));
        if (data.status === 'cloning' || data.status === 'scanning') {
          pollTimerRef.current = setTimeout(poll, 1000);
        } else {
          stopElapsedTimer();
        }
      } catch (err) {
        console.error('Poll failed:', err);
        pollTimerRef.current = setTimeout(poll, 3000);
      }
    };
    pollTimerRef.current = setTimeout(poll, 500);
  }, [startElapsedTimer, stopElapsedTimer]);

  const handleScan = async () => {
    const type = detectInputType(input);
    if (!type) return;

    setLoading(true);
    setError(null);
    setResult(null);
    setRepoResult(null);
    setElapsed(0);
    if (pollTimerRef.current) clearTimeout(pollTimerRef.current);
    stopElapsedTimer();
    onResumeFeed?.();

    try {
      if (type === 'code') {
        const data = await scanCode(input);
        setResult(data);
      } else if (type === 'repo') {
        const data = await scanRepo(input);
        const jobId = data.job_id || data._id;
        setRepoResult({
          ...data,
          job_id: jobId,
          repo_url: input.trim(),
          _jobData: { status: 'cloning', file_count: 0, files_scanned: 0, finding_count: 0, findings: {} }
        });
        startRepoPolling(jobId);
      } else if (type === 'dast') {
        const data = await dastScan(input, dastMode, verboseEvidence);
        setResult(data);
      }
    } catch (err) {
      stopElapsedTimer();
      setError(err.response?.data?.error || err.message || 'Scan failed');
    } finally {
      setLoading(false);
    }
  };

  const handleKeyDown = (e) => {
    if ((e.metaKey || e.ctrlKey) && e.key === 'Enter') {
      handleScan();
    }
  };

  const config = detectedType ? TYPE_CONFIG[detectedType] : null;
  const Icon = config?.icon;

  return (
    <div className="unified-scanner">
      <div className="scanner-input-area">
        <div className="input-row">
          <textarea
            value={input}
            onChange={handleInputChange}
            onKeyDown={handleKeyDown}
            placeholder={detectedType
              ? TYPE_CONFIG[detectedType].hint
              : 'Paste code, GitHub repo URL, or website URL...'
            }
            rows={detectedType === 'code' ? 10 : 2}
            className={`scanner-textarea ${detectedType ? 'has-type' : ''}`}
          />
          {detectedType && (
            <div className="type-indicator" style={{ borderColor: config.color }}>
              <Icon className="icon-xs" style={{ color: config.color }} />
              <span style={{ color: config.color }}>{config.label}</span>
            </div>
          )}
        </div>

          <div className="scanner-controls">
          <div className="scanner-controls-left">
            {detectedType && (
              <span className="detected-label" style={{ color: config.color }}>
                <Icon className="icon-xs" /> {config.label} detected
              </span>
            )}
            {detectedType === 'dast' && isLocalhost(input) && (
              <span className="scanner-warning">
                <AlertTriangle className="icon-xs" /> Scanning localhost — use an external URL for real targets
              </span>
            )}
            {!detectedType && input.length === 0 && (
              <span className="scanner-hint">
                <Search className="icon-xs" /> Auto-detects input type
              </span>
            )}
          </div>

          <div className="scanner-controls-right">
            {detectedType === 'dast' && (
              <>
                <select value={dastMode} onChange={(e) => setDastMode(e.target.value)} className="mode-select-sm">
                  <option value="passive">Passive</option>
                  <option value="active">Active</option>
                </select>
                <label className="verbose-toggle-sm">
                  <input type="checkbox" checked={verboseEvidence} onChange={(e) => setVerboseEvidence(e.target.checked)} />
                  Verbose
                </label>
              </>
            )}
            <button
              onClick={handleScan}
              disabled={loading || !detectedType}
              className="scan-btn"
            >
              {loading ? (
                <><Loader className="icon-xs spin" /> Scanning...</>
              ) : (
                <><Search className="icon-xs" /> Scan</>
              )}
            </button>
          </div>
        </div>
      </div>

      {error && (
        <div className="scan-error">
          <AlertTriangle className="icon-sm" /> {error}
        </div>
      )}

      {result && detectedType === 'code' && (
        <div className="scan-results">
          {result.prediction === 'not_vulnerable' ? (
            <div className="scan-clean">
              <CheckCircle className="icon" />
              <span>No vulnerabilities detected</span>
            </div>
          ) : (
            <>
              <FindingCard event={{
                event_type: 'code',
                prediction: result.prediction,
                confidence: result.confidence,
                severity: result.severity || result.explanation?.severity || 'info',
                status: result.status,
                explanation: result.explanation,
                suggested_fix: result.suggested_fix
              }} showType={false} />

              {result.top_predictions && result.top_predictions.length > 1 && (
                <div className="top-predictions">
                  <h4>Other Possibilities</h4>
                  <ul>
                    {result.top_predictions.slice(1).map((pred, idx) => (
                      <li key={idx}>
                        <span className="pred-class">{pred.class.replace(/_/g, ' ')}</span>
                        <span className="pred-cwe">{pred.cwe}</span>
                        <span className="pred-confidence">{(pred.confidence * 100).toFixed(0)}%</span>
                      </li>
                    ))}
                  </ul>
                </div>
              )}
            </>
          )}
        </div>
      )}

      {result && detectedType === 'dast' && (
        <div className="scan-results">
          <div className="result-header">
            <span className="result-target">{result.target_url}</span>
            <div className="result-meta">
              <span className={`mode-badge ${result.mode}`}>{result.mode}</span>
              <span className="result-count">{result.finding_count} findings</span>
            </div>
          </div>
          {result.findings.length === 0 ? (
            <div className="scan-clean">
              <CheckCircle className="icon" />
              <span>No issues found</span>
            </div>
          ) : (
            <div className="events-list">
              {result.findings.map((f, i) => (
                <FindingCard key={f.event_id || i} event={{
                  ...f,
                  event_type: 'dast',
                  mode: result.mode,
                  timestamp: new Date().toISOString()
                }} showType={true} />
              ))}
            </div>
          )}
        </div>
      )}

      {repoResult && (
        <div className="scan-results">
          <div className="result-header">
            <span className="result-target">{repoResult.repo_url || repoResult.repo_url}</span>
            <div className="result-meta">
              <span className={`status-badge status-${repoResult._jobData?.status || 'cloning'}`}>
                {repoResult._jobData?.status || 'cloning'}
              </span>
              <span className="result-count timer">{formatTime(elapsed)}</span>
            </div>
          </div>

          {repoResult._jobData && (
            <>
              {(repoResult._jobData.status === 'cloning' || repoResult._jobData.status === 'scanning') && (
                <div className="repo-progress">
                  <div className="progress-phases">
                    <div className={`phase ${repoResult._jobData.status === 'cloning' || repoResult._jobData.status === 'scanning' ? 'active' : 'done'}`}>
                      <span className="phase-dot" />
                      Cloning
                    </div>
                    <div className={`phase ${repoResult._jobData.status === 'scanning' ? 'active' : repoResult._jobData.status === 'completed' ? 'done' : ''}`}>
                      <span className="phase-dot" />
                      Scanning
                    </div>
                    <div className={`phase ${repoResult._jobData.status === 'completed' ? 'done' : ''}`}>
                      <span className="phase-dot" />
                      Done
                    </div>
                  </div>

                  {repoResult._jobData.status === 'cloning' && (
                    <div className="progress-status">
                      <Loader className="icon-sm spin" /> Cloning repository... <span className="timer-live">{formatTime(elapsed)}</span>
                    </div>
                  )}

                  {repoResult._jobData.status === 'scanning' && (
                    <div className="progress-status">
                      <Loader className="icon-sm spin" /> Scanning files...
                      <span className="progress-numbers"> {repoResult._jobData.files_scanned}/{repoResult._jobData.file_count} files</span>
                      {repoResult._jobData.finding_count > 0 && (
                        <span className="scan-finding-count"> — {repoResult._jobData.finding_count} finding{repoResult._jobData.finding_count !== 1 ? 's' : ''}</span>
                      )}
                      <span className="timer-live">{formatTime(elapsed)}</span>
                    </div>
                  )}

                  {repoResult._jobData.file_count > 0 && (
                    <div className="progress-bar-container">
                      <div
                        className="progress-bar"
                        style={{ width: `${(repoResult._jobData.files_scanned / repoResult._jobData.file_count) * 100}%` }}
                      />
                      <span className="progress-pct">
                        {Math.round((repoResult._jobData.files_scanned / repoResult._jobData.file_count) * 100)}%
                      </span>
                    </div>
                  )}

                  {repoResult._jobData.status === 'scanning' && repoResult._jobData.file_count > 0 && repoResult._jobData.files_scanned > 2 && (
                    <div className="progress-eta">
                      {(() => {
                        const filesPerSec = repoResult._jobData.files_scanned / Math.max(elapsed, 1);
                        const remaining = repoResult._jobData.file_count - repoResult._jobData.files_scanned;
                        const eta = Math.ceil(remaining / Math.max(filesPerSec, 0.1));
                        return `~${formatTime(eta)} remaining`;
                      })()}
                    </div>
                  )}
                </div>
              )}

              {repoResult._jobData.status === 'completed' && repoResult._jobData.finding_count === 0 && (
                <div className="scan-clean">
                  <CheckCircle className="icon" />
                  <span>No vulnerabilities found in {repoResult._jobData.file_count} files — completed in {formatTime(elapsed)}</span>
                </div>
              )}

              {repoResult._jobData.status === 'failed' && (
                <div className="scan-error">
                  <AlertTriangle className="icon-sm" />
                  <span>{repoResult._jobData.error || 'Clone failed — check if the repo URL is valid'}</span>
                </div>
              )}

              {repoResult._jobData.status === 'completed' && repoResult._jobData.findings && Object.keys(repoResult._jobData.findings).length > 0 && (
                <div className="scan-summary">
                  <CheckCircle className="icon" />
                  <span>{repoResult._jobData.finding_count} finding{repoResult._jobData.finding_count !== 1 ? 's' : ''} in {repoResult._jobData.file_count} files — completed in {formatTime(elapsed)}</span>
                </div>
              )}

              {repoResult._jobData.findings && Object.keys(repoResult._jobData.findings).length > 0 && (
                <div className="events-list">
                  {Object.entries(repoResult._jobData.findings).map(([filePath, findings]) => (
                    <div key={filePath} className="file-group">
                      <h4 className="file-path">{filePath}</h4>
                      {findings.map((f, i) => (
                        <FindingCard key={i} event={{
                          event_type: 'scan_repo',
                          prediction: f.prediction,
                          confidence: f.confidence,
                          severity: f.explanation?.severity || 'medium',
                          status: 'human_review',
                          explanation: f.explanation,
                          suggested_fix: f.suggested_fix
                        }} showType={false} />
                      ))}
                    </div>
                  ))}
                </div>
              )}
            </>
          )}
        </div>
      )}
    </div>
  );
};

export default UnifiedScanner;
