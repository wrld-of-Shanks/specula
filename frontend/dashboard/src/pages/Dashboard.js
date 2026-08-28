import React, { useState, useEffect } from 'react';
import { scanCode, scanRepo, dastScan, fetchStats, fetchEvents } from '../services/api';

function detectType(input) {
  const trimmed = input.trim();
  if (!trimmed) return null;
  if (/^https?:\/\//.test(trimmed)) {
    if (/github\.com/.test(trimmed) || /gitlab\.com/.test(trimmed)) return 'repo';
    return 'dast';
  }
  return 'code';
}

function Dashboard() {
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const [input, setInput] = useState('');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState('');
  const [stats, setStats] = useState({ total: 0, critical: 0, high: 0, medium: 0, dast: 0, code: 0, repo: 0 });
  const [scanMode, setScanMode] = useState('passive');

  const detectedType = detectType(input);

  useEffect(() => {
    loadStats();
  }, []);

  const loadStats = async () => {
    try {
      const data = await fetchStats();
      if (data) {
        setStats({
          total: data.total || 0,
          critical: data.critical || 0,
          high: data.high || 0,
          medium: data.medium || 0,
          dast: data.dast || 0,
          code: data.code || 0,
          repo: data.repo || 0
        });
      }
    } catch (err) {
      console.error('Failed to load stats:', err);
    }
  };

  const updateStatsFromResult = (data, type) => {
    setStats(prev => {
      const newStats = { ...prev };
      newStats.total += 1;
      newStats[type] = (newStats[type] || 0) + 1;

      if (data) {
        const sev = data.severity || '';
        if (sev === 'critical') newStats.critical += 1;
        else if (sev === 'high') newStats.high += 1;
        else if (sev === 'medium') newStats.medium += 1;

        if (data.findings) {
          data.findings.forEach(f => {
            const fs = f.severity || '';
            if (fs === 'critical') newStats.critical += 1;
            else if (fs === 'high') newStats.high += 1;
            else if (fs === 'medium') newStats.medium += 1;
          });
        }
      }
      return newStats;
    });
  };

  const handleScan = async () => {
    if (!input.trim() || !detectedType) return;

    setLoading(true);
    setError('');
    setResult(null);

    try {
      let data;
      if (detectedType === 'code') {
        data = await scanCode(input.trim());
      } else if (detectedType === 'repo') {
        data = await scanRepo(input.trim());
      } else if (detectedType === 'dast') {
        data = await dastScan(input.trim(), scanMode);
      }
      setResult(data);
      updateStatsFromResult(data, detectedType);
    } catch (err) {
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

  return (
    <div style={{
      minHeight: '100vh',
      backgroundImage: `url(${process.env.PUBLIC_URL}/BG.png)`,
      backgroundSize: 'cover',
      backgroundPosition: 'center',
      fontFamily: '-apple-system, BlinkMacSystemFont, sans-serif'
    }}>
      {/* Sidebar Overlay */}
      <div
        onClick={() => setSidebarOpen(false)}
        style={{
          position: 'fixed',
          inset: 0,
          background: 'rgba(0,0,0,0.5)',
          zIndex: 40,
          opacity: sidebarOpen ? 1 : 0,
          pointerEvents: sidebarOpen ? 'auto' : 'none',
          transition: 'opacity 0.3s ease'
        }}
      />

      {/* Side Sheet */}
      <div style={{
        position: 'fixed',
        left: 0,
        top: 0,
        height: '100%',
        width: '280px',
        background: 'rgba(255, 255, 255, 0.05)',
        backdropFilter: 'blur(10px)',
        WebkitBackdropFilter: 'blur(10px)',
        borderRight: '1px solid rgba(255,255,255,0.1)',
        zIndex: 50,
        transform: sidebarOpen ? 'translateX(0)' : 'translateX(-100%)',
        transition: 'transform 0.3s ease',
        display: 'flex',
        flexDirection: 'column'
      }}>
        <div style={{
          padding: '10px 20px',
          borderBottom: '1px solid rgba(255,255,255,0.1)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between'
        }}>
          <span style={{
            fontSize: '16px',
            fontWeight: '600',
            color: 'white'
          }}>
            Specula
          </span>
          <button
            onClick={() => setSidebarOpen(false)}
            style={{
              padding: '2px',
              background: 'transparent',
              border: 'none',
              borderRadius: '4px',
              cursor: 'pointer'
            }}
          >
            <img
              src="/dashboard/nono.png"
              alt="Close"
              style={{
                width: '28px',
                height: '28px',
                borderRadius: '50%'
              }}
            />
          </button>
        </div>
      </div>

      <header style={{
        display: 'flex',
        justifyContent: 'center',
        alignItems: 'center',
        padding: '16px 24px',
        borderBottom: '1px solid rgba(255,255,255,0.1)',
        background: 'rgba(255,255,255,0.05)',
        backdropFilter: 'blur(10px)',
        WebkitBackdropFilter: 'blur(10px)',
        position: 'relative'
      }}>
        <button
          onClick={() => setSidebarOpen(!sidebarOpen)}
          style={{
            position: 'absolute',
            left: '24px',
            padding: '4px',
            background: 'transparent',
            border: 'none',
            cursor: 'pointer',
            borderRadius: '6px'
          }}
        >
          <img
            src={`${process.env.PUBLIC_URL}/nono.png`}
            alt="Menu"
            style={{
              width: '36px',
              height: '36px',
              borderRadius: '50%'
            }}
          />
        </button>
        <h1 style={{
          fontSize: '20px',
          fontWeight: '600',
          color: 'white'
        }}>
          Specula
        </h1>
      </header>

      <main style={{
        display: 'flex',
        flexDirection: 'column',
        alignItems: 'center',
        justifyContent: 'center',
        minHeight: 'calc(100vh - 64px)',
        padding: '40px 24px',
        gap: '24px'
      }}>
        {/* Stats Box */}
        <div style={{
          width: '100%',
          maxWidth: '600px',
          backgroundImage: `url(${process.env.PUBLIC_URL}/veve.png)`,
          backgroundSize: 'cover',
          backgroundPosition: 'center',
          borderRadius: '16px',
          border: '1px solid rgba(255, 255, 255, 0.1)',
          padding: '20px 24px',
          position: 'relative',
          overflow: 'hidden'
        }}>
          <div style={{
            position: 'absolute',
            inset: 0,
            background: 'rgba(0,0,0,0.4)',
            backdropFilter: 'blur(2px)',
            WebkitBackdropFilter: 'blur(2px)'
          }} />
          <div style={{
            position: 'relative',
            zIndex: 1,
            display: 'flex',
            justifyContent: 'space-between',
            flexWrap: 'wrap',
            gap: '16px'
          }}>
            <div style={{ display: 'flex', gap: '20px' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                <span style={{ color: 'white', fontSize: '13px' }}>Total</span>
                <span style={{ color: 'white', fontWeight: '600', fontSize: '14px' }}>({stats.total})</span>
              </div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                <span style={{ color: '#ef4444', fontSize: '13px' }}>Critical</span>
                <span style={{ color: '#ef4444', fontWeight: '600', fontSize: '14px' }}>({stats.critical})</span>
              </div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                <span style={{ color: '#fb923c', fontSize: '13px' }}>High</span>
                <span style={{ color: '#fb923c', fontWeight: '600', fontSize: '14px' }}>({stats.high})</span>
              </div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                <span style={{ color: '#eab308', fontSize: '13px' }}>Medium</span>
                <span style={{ color: '#eab308', fontWeight: '600', fontSize: '14px' }}>({stats.medium})</span>
              </div>
            </div>
            <div style={{ display: 'flex', gap: '20px' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                <span style={{ color: 'white', fontSize: '13px' }}>DAST</span>
                <span style={{ color: 'white', fontWeight: '600', fontSize: '14px' }}>({stats.dast})</span>
              </div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                <span style={{ color: 'white', fontSize: '13px' }}>Code</span>
                <span style={{ color: 'white', fontWeight: '600', fontSize: '14px' }}>({stats.code})</span>
              </div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                <span style={{ color: 'white', fontSize: '13px' }}>Repo</span>
                <span style={{ color: 'white', fontWeight: '600', fontSize: '14px' }}>({stats.repo})</span>
              </div>
            </div>
          </div>
        </div>

        {/* Input Box */}
        <div style={{
          width: '100%',
          maxWidth: '600px',
          backgroundImage: `url(${process.env.PUBLIC_URL}/red.jpeg)`,
          backgroundSize: 'cover',
          backgroundPosition: 'center',
          borderRadius: '16px',
          border: '1px solid rgba(255, 255, 255, 0.1)',
          padding: '24px',
          position: 'relative',
          overflow: 'hidden'
        }}>
          <div style={{
            position: 'absolute',
            inset: 0,
            background: 'rgba(0,0,0,0.4)',
            backdropFilter: 'blur(2px)',
            WebkitBackdropFilter: 'blur(2px)'
          }} />
          <div style={{ position: 'relative', zIndex: 1 }}>
            <textarea
              value={input}
              onChange={(e) => setInput(e.target.value)}
              onKeyDown={handleKeyDown}
              placeholder="Paste code, GitHub repo URL, or website URL..."
              style={{
                width: '100%',
                minHeight: '120px',
                background: 'rgba(255, 255, 255, 0.1)',
                border: '1px solid rgba(255, 255, 255, 0.2)',
                borderRadius: '8px',
                padding: '16px',
                color: 'white',
                fontSize: '14px',
                fontFamily: 'monospace',
                resize: 'vertical',
                outline: 'none'
              }}
            />
            <div style={{
              display: 'flex',
              justifyContent: 'space-between',
              alignItems: 'center',
              marginTop: '16px'
            }}>
              <span style={{
                color: 'white',
                fontSize: '13px',
                display: 'flex',
                alignItems: 'center',
                gap: '6px'
              }}>
                {detectedType && (
                  <span style={{
                    padding: '2px 8px',
                    background: 'rgba(255,255,255,0.15)',
                    borderRadius: '4px',
                    fontSize: '11px',
                    textTransform: 'uppercase'
                  }}>
                    {detectedType === 'code' ? 'Code' : detectedType === 'repo' ? 'Repo' : 'URL'} detected
                  </span>
                )}
                {!detectedType && (
                  <>
                    <span style={{
                      width: '6px',
                      height: '6px',
                      borderRadius: '50%',
                      background: 'white'
                    }} />
                    Auto-detects input type
                  </>
                )}
              </span>
              <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                {detectedType === 'dast' && (
                  <div style={{
                    display: 'flex',
                    background: 'rgba(255,255,255,0.1)',
                    borderRadius: '6px',
                    border: '1px solid rgba(255,255,255,0.15)',
                    overflow: 'hidden'
                  }}>
                    <button
                      onClick={() => setScanMode('passive')}
                      style={{
                        padding: '5px 12px',
                        background: scanMode === 'passive' ? 'rgba(255,255,255,0.25)' : 'transparent',
                        border: 'none',
                        color: 'white',
                        fontSize: '11px',
                        fontWeight: scanMode === 'passive' ? '600' : '400',
                        cursor: 'pointer',
                        transition: 'background 0.2s'
                      }}
                    >
                      Passive
                    </button>
                    <button
                      onClick={() => setScanMode('active')}
                      style={{
                        padding: '5px 12px',
                        background: scanMode === 'active' ? 'rgba(255,255,255,0.25)' : 'transparent',
                        border: 'none',
                        color: 'white',
                        fontSize: '11px',
                        fontWeight: scanMode === 'active' ? '600' : '400',
                        cursor: 'pointer',
                        transition: 'background 0.2s'
                      }}
                    >
                      Active
                    </button>
                  </div>
                )}
                <button
                  onClick={handleScan}
                  disabled={loading || !detectedType}
                  style={{
                    padding: '8px 24px',
                    background: 'white',
                    border: 'none',
                    borderRadius: '8px',
                    color: '#111',
                    fontSize: '13px',
                    fontWeight: '600',
                    cursor: loading || !detectedType ? 'not-allowed' : 'pointer',
                    opacity: loading || !detectedType ? 0.5 : 1
                  }}
                >
                  {loading ? 'Scanning...' : 'Scan'}
                </button>
              </div>
            </div>
          </div>
        </div>

        {/* Error */}
        {error && (
          <div style={{
            width: '100%',
            maxWidth: '600px',
            background: 'rgba(239, 68, 68, 0.15)',
            border: '1px solid rgba(239, 68, 68, 0.3)',
            borderRadius: '8px',
            padding: '12px 16px',
            color: '#fca5a5',
            fontSize: '13px'
          }}>
            {error}
          </div>
        )}

        {/* Results */}
        {result && (
          <div style={{
            width: '100%',
            maxWidth: '600px',
            background: 'rgba(255, 255, 255, 0.05)',
            backdropFilter: 'blur(15px)',
            WebkitBackdropFilter: 'blur(15px)',
            borderRadius: '16px',
            border: '1px solid rgba(255, 255, 255, 0.1)',
            padding: '20px 24px'
          }}>
            <h3 style={{
              fontSize: '14px',
              fontWeight: '600',
              color: 'white',
              marginBottom: '12px'
            }}>
              Scaned Results
            </h3>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
              {result.findings ? (
                result.findings.length > 0 ? result.findings.map((f, idx) => (
                  <div key={f.event_id || idx} style={{
                    background: 'rgba(0,0,0,0.3)',
                    borderRadius: '8px',
                    padding: '12px',
                    border: `1px solid ${f.severity === 'critical' ? 'rgba(239,68,68,0.4)' : f.severity === 'high' ? 'rgba(251,146,60,0.4)' : f.severity === 'medium' ? 'rgba(234,179,8,0.4)' : 'rgba(255,255,255,0.08)'}`
                  }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '6px' }}>
                      <span style={{ fontSize: '11px', color: 'white', fontWeight: '600' }}>
                        Finding #{idx + 1}
                      </span>
                      <span style={{
                        fontSize: '10px',
                        padding: '2px 6px',
                        borderRadius: '4px',
                        background: f.severity === 'critical' ? 'rgba(239,68,68,0.3)' : f.severity === 'high' ? 'rgba(251,146,60,0.3)' : f.severity === 'medium' ? 'rgba(234,179,8,0.3)' : 'rgba(255,255,255,0.1)',
                        color: 'white',
                        textTransform: 'uppercase'
                      }}>
                        {f.severity || 'info'}
                      </span>
                    </div>
                    <div style={{ fontSize: '12px', color: 'rgba(255,255,255,0.7)', marginBottom: '4px' }}>
                      <strong>{f.check_name || f.prediction || 'Unknown'}</strong>
                    </div>
                    {f.explanation?.what && (
                      <div style={{ fontSize: '11px', color: 'rgba(255,255,255,0.5)', marginBottom: '4px' }}>
                        {f.explanation.what}
                      </div>
                    )}
                    {f.explanation?.location && (
                      <div style={{ fontSize: '10px', color: 'rgba(255,255,255,0.4)' }}>
                        {f.explanation.location}
                      </div>
                    )}
                    {f.explanation?.reference && (
                      <div style={{ fontSize: '10px', color: 'rgba(255,255,255,0.4)', marginTop: '4px' }}>
                        {f.explanation.reference.cwe} | {f.explanation.reference.owasp}
                      </div>
                    )}
                  </div>
                )) : (
                  <div style={{ color: 'rgba(255,255,255,0.5)', fontSize: '13px', textAlign: 'center', padding: '20px' }}>
                    No findings detected
                  </div>
                )
              ) : (
                Object.entries(result).filter(([k]) => !['findings', 'target_url', 'mode', 'finding_count'].includes(k)).map(([key, value]) => (
                  <div key={key}>
                    <div style={{
                      fontSize: '11px',
                      color: 'rgba(255,255,255,0.5)',
                      textTransform: 'uppercase',
                      letterSpacing: '0.05em',
                      marginBottom: '4px'
                    }}>
                      {key.replace(/_/g, ' ')}
                    </div>
                    <div style={{
                      background: 'rgba(0,0,0,0.3)',
                      borderRadius: '8px',
                      padding: '10px 12px',
                      color: 'white',
                      fontSize: '12px',
                      fontFamily: 'monospace',
                      wordBreak: 'break-word',
                      border: '1px solid rgba(255,255,255,0.05)',
                      maxHeight: '400px',
                      overflowY: 'auto'
                    }}>
                      {Array.isArray(value) ? (
                        <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
                          {value.map((item, idx) => (
                            <div key={idx} style={{
                              background: 'rgba(255,255,255,0.05)',
                              borderRadius: '6px',
                              padding: '10px',
                              border: '1px solid rgba(255,255,255,0.08)'
                            }}>
                              <div style={{ fontSize: '10px', color: 'white', marginBottom: '6px', borderBottom: '1px solid rgba(255,255,255,0.06)', paddingBottom: '4px' }}>
                                #{idx + 1}
                              </div>
                              <pre style={{ margin: 0, whiteSpace: 'pre-wrap' }}>
                                {typeof item === 'object' ? JSON.stringify(item, null, 2) : String(item)}
                              </pre>
                            </div>
                          ))}
                        </div>
                      ) : typeof value === 'object' ? (
                        <pre style={{ margin: 0, whiteSpace: 'pre-wrap' }}>{JSON.stringify(value, null, 2)}</pre>
                      ) : (
                        String(value)
                      )}
                    </div>
                  </div>
                ))
              )}
            </div>
          </div>
        )}
      </main>
    </div>
  );
}

export default Dashboard;
