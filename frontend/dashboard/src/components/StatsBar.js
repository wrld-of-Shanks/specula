import React from 'react';
import { Shield, Globe, Code, GitBranch, AlertTriangle } from 'lucide-react';

const StatsBar = ({ events }) => {
  const total = events.length;
  const critical = events.filter(e => e.severity === 'critical').length;
  const high = events.filter(e => e.severity === 'high').length;
  const medium = events.filter(e => e.severity === 'medium').length;
  const network = events.filter(e => e.event_type === 'network').length;
  const code = events.filter(e => e.event_type === 'code').length;
  const dast = events.filter(e => e.event_type === 'dast').length;
  const repo = events.filter(e => e.event_type === 'scan_repo').length;

  return (
    <div className="stats-bar">
      <div className="stat-pill">
        <Shield className="stat-pill-icon" style={{ color: '#3b82f6' }} />
        <span className="stat-pill-value">{total}</span>
        <span className="stat-pill-label">Total</span>
      </div>
      <div className="stat-divider" />
      <div className="stat-pill">
        <AlertTriangle className="stat-pill-icon" style={{ color: '#ef4444' }} />
        <span className="stat-pill-value">{critical + high}</span>
        <span className="stat-pill-label">Critical/High</span>
      </div>
      <div className="stat-pill">
        <AlertTriangle className="stat-pill-icon" style={{ color: '#eab308' }} />
        <span className="stat-pill-value">{medium}</span>
        <span className="stat-pill-label">Medium</span>
      </div>
      <div className="stat-divider" />
      <div className="stat-pill">
        <Globe className="stat-pill-icon" style={{ color: '#ef4444' }} />
        <span className="stat-pill-value">{dast}</span>
        <span className="stat-pill-label">DAST</span>
      </div>
      <div className="stat-pill">
        <Code className="stat-pill-icon" style={{ color: '#06b6d4' }} />
        <span className="stat-pill-value">{code}</span>
        <span className="stat-pill-label">Code</span>
      </div>
      <div className="stat-pill">
        <GitBranch className="stat-pill-icon" style={{ color: '#f59e0b' }} />
        <span className="stat-pill-value">{repo}</span>
        <span className="stat-pill-label">Repo</span>
      </div>
    </div>
  );
};

export default StatsBar;
