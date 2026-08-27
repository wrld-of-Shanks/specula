import React, { useState, useEffect } from 'react';
import { Globe, Search, AlertTriangle, CheckCircle, Lock, Unlock } from 'lucide-react';
import { dastScan, getAuthorizedTargets, addAuthorizedTarget, removeAuthorizedTarget } from '../services/api';
import FindingCard from './FindingCard';

const DastScanner = () => {
  const [targetUrl, setTargetUrl] = useState('');
  const [mode, setMode] = useState('passive');
  const [verboseEvidence, setVerboseEvidence] = useState(false);
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [authorizedTargets, setAuthorizedTargets] = useState([]);
  const [newTarget, setNewTarget] = useState('');
  const [newTargetNote, setNewTargetNote] = useState('');

  useEffect(() => {
    loadAuthorizedTargets();
  }, []);

  const loadAuthorizedTargets = async () => {
    try {
      const data = await getAuthorizedTargets();
      setAuthorizedTargets(data);
    } catch (err) {
      console.error('Failed to load targets');
    }
  };

  const handleScan = async () => {
    if (!targetUrl.trim()) return;
    setLoading(true);
    setError(null);
    setResult(null);
    try {
      const data = await dastScan(targetUrl, mode, verboseEvidence);
      setResult(data);
    } catch (err) {
      setError(err.response?.data?.error || 'Scan failed');
    } finally {
      setLoading(false);
    }
  };

  const handleAddTarget = async () => {
    if (!newTarget.trim()) return;
    try {
      await addAuthorizedTarget(newTarget, newTargetNote);
      setNewTarget('');
      setNewTargetNote('');
      loadAuthorizedTargets();
    } catch (err) {
      setError('Failed to add target');
    }
  };

  const handleRemoveTarget = async (target) => {
    try {
      await removeAuthorizedTarget(target);
      loadAuthorizedTargets();
    } catch (err) {
      setError('Failed to remove target');
    }
  };

  return (
    <div className="dast-scanner">
      <h2><Globe className="icon" /> DAST Scanner</h2>

      <div className="dast-controls">
        <div className="scan-input-group">
          <input type="url" value={targetUrl} onChange={(e) => setTargetUrl(e.target.value)}
            placeholder="https://example.com" className="repo-input" />
          <select value={mode} onChange={(e) => setMode(e.target.value)} className="mode-select">
            <option value="passive">Passive Only</option>
            <option value="active">Active (requires authorization)</option>
          </select>
          <label className="verbose-toggle">
            <input type="checkbox" checked={verboseEvidence} onChange={(e) => setVerboseEvidence(e.target.checked)} />
            Verbose Evidence
          </label>
          <button onClick={handleScan} disabled={loading} className="scan-button">
            {loading ? 'Scanning...' : <><Search className="icon" /> Scan Target</>}
          </button>
        </div>
      </div>

      {error && <div className="error-message"><AlertTriangle className="icon" /> {error}</div>}

      {result && (
        <div className="scan-result">
          <div className="result-header">
            <h3>Scan Results: {result.target_url}</h3>
            <div className="result-meta">
              <span className={`mode-badge ${result.mode}`}>{result.mode}</span>
              <span>{result.finding_count} findings</span>
            </div>
          </div>

          {result.findings.length === 0 ? (
            <div className="no-findings"><CheckCircle className="icon" /> No issues found</div>
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

      <div className="authorized-targets-section">
        <h3><Lock className="icon-sm" /> Authorized Targets (for Active Scans)</h3>
        <div className="add-target-form">
          <input type="text" value={newTarget} onChange={(e) => setNewTarget(e.target.value)}
            placeholder="example.com" className="target-input" />
          <input type="text" value={newTargetNote} onChange={(e) => setNewTargetNote(e.target.value)}
            placeholder="Note (optional)" className="target-note-input" />
          <button onClick={handleAddTarget} className="add-target-btn">Add</button>
        </div>
        <div className="targets-list">
          {authorizedTargets.length === 0 ? (
            <p className="no-events">No authorized targets. Only localhost is allowed for active scans.</p>
          ) : authorizedTargets.map(t => (
            <div key={t.target} className="target-item">
              <span className="target-host"><Globe className="icon-sm" /> {t.target}</span>
              <span className="target-note">{t.note}</span>
              <button onClick={() => handleRemoveTarget(t.target)} className="remove-btn">
                <Unlock className="icon-sm" />
              </button>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};

export default DastScanner;
