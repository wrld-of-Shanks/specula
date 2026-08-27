import React, { useState } from 'react';
import { Code, Search, AlertTriangle } from 'lucide-react';
import { scanCode } from '../services/api';
import FindingCard from './FindingCard';

const CodeScanner = () => {
  const [code, setCode] = useState('');
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  const handleScan = async () => {
    if (!code.trim()) {
      setError('Please enter some code to scan');
      return;
    }

    setLoading(true);
    setError(null);
    setResult(null);

    try {
      const scanResult = await scanCode(code);
      setResult(scanResult);
    } catch (err) {
      setError(err.message || 'Failed to scan code');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="code-scanner">
      <h2>
        <Code className="icon" />
        Code Vulnerability Scanner
      </h2>

      <div className="scanner-input">
        <textarea
          value={code}
          onChange={(e) => setCode(e.target.value)}
          placeholder="Paste your code here (JavaScript, Python, Java, etc.)..."
          rows={12}
        />
        <button
          onClick={handleScan}
          disabled={loading || !code.trim()}
          className="scan-button"
        >
          {loading ? 'Scanning...' : <><Search className="icon" /> Scan Code</>}
        </button>
      </div>

      {error && (
        <div className="error-message">
          <AlertTriangle className="icon" />
          {error}
        </div>
      )}

      {result && (
        <div className="scan-result">
          {result.prediction === 'not_vulnerable' ? (
            <div className="no-events" style={{ color: '#10b981' }}>
              <p>No vulnerabilities detected in this code.</p>
            </div>
          ) : (
            <FindingCard event={{
              event_type: 'code',
              prediction: result.prediction,
              confidence: result.confidence,
              severity: result.severity || result.explanation?.severity || 'info',
              status: result.status,
              explanation: result.explanation,
              suggested_fix: result.suggested_fix
            }} showType={false} />
          )}

          {result.top_predictions && result.top_predictions.length > 0 && (
            <div className="top-predictions">
              <h4>Top Predictions</h4>
              <ul>
                {result.top_predictions.map((pred, idx) => (
                  <li key={idx}>
                    <span className="pred-class">{pred.class}</span>
                    <span className="pred-cwe">{pred.cwe}</span>
                    <span className="pred-confidence">
                      {(pred.confidence * 100).toFixed(1)}%
                    </span>
                  </li>
                ))}
              </ul>
            </div>
          )}
        </div>
      )}
    </div>
  );
};

export default CodeScanner;
