import React from 'react';
import { AlertTriangle, Shield, Info, CheckCircle, MapPin, BookOpen, Wrench, MessageCircle, Check, Code, GitBranch, Globe } from 'lucide-react';

const getSeverityColor = (severity) => {
  switch (severity) {
    case 'critical': return '#ef4444';
    case 'high': return '#f97316';
    case 'medium': return '#eab308';
    case 'low': return '#3b82f6';
    default: return '#6b7280';
  }
};

const getSeverityIcon = (severity) => {
  switch (severity) {
    case 'critical':
    case 'high':
      return <AlertTriangle className="icon critical" />;
    case 'medium':
      return <Shield className="icon medium" />;
    case 'low':
      return <Info className="icon low" />;
    default:
      return <CheckCircle className="icon info" />;
  }
};

const getSourceInfo = (event) => {
  const type = event.event_type;
  const source = event.source || '';

  switch (type) {
    case 'dast':
      return {
        label: 'website',
        icon: <Globe className="icon-xs" />,
        detail: source,
        where: event.explanation?.location || source
      };
    case 'scan_repo':
      return {
        label: 'repo',
        icon: <GitBranch className="icon-xs" />,
        detail: source,
        where: event.file_path
          ? `${event.file_path}${event.line_range?.start ? ` L${event.line_range.start}-${event.line_range.end}` : ''}`
          : source
      };
    case 'code':
      return {
        label: 'code',
        icon: <Code className="icon-xs" />,
        detail: null,
        where: event.explanation?.location || 'manual scan'
      };
    case 'network':
      return {
        label: 'network',
        icon: <Info className="icon-xs" />,
        detail: source,
        where: source
      };
    default:
      return {
        label: type || 'unknown',
        icon: null,
        detail: source,
        where: event.explanation?.location || source
      };
  }
};

const formatTimestamp = (ts) => ts ? new Date(ts).toLocaleString() : null;

const FindingCard = ({ event, showType = true, showFile = false }) => {
  const exp = event.explanation || {};
  const rem = exp.remediation || {};
  const certaintyType = event.certainty_type || exp.certainty_type || null;
  const isConfirmed = certaintyType === 'confirmed';
  const confidence = event.confidence;
  const sourceInfo = getSourceInfo(event);

  return (
    <div className={`event-card ${event.severity} ${isConfirmed ? 'confirmed' : 'inferred'}`}>
      <div className="event-header">
        <div className="event-icon">
          {getSeverityIcon(event.severity)}
        </div>
        <div className="event-info">
          <span className="event-type">
            {showType && <span className={`event-type-badge ${event.event_type}`}>{event.event_type}</span>}
            {' '}{event.prediction?.replace(/_/g, ' ')}
          </span>
          <span className="event-time">
            <span className={`source-badge source-${event.event_type}`}>
              {sourceInfo.icon} {sourceInfo.label}
            </span>
            {event.mode && <span className={`mode-badge ${event.mode}`}>{event.mode}</span>}
            {!event.file_path && !event.mode && event.timestamp && ` ${formatTimestamp(event.timestamp)}`}
          </span>
        </div>
        <div className="severity-badge" style={{ backgroundColor: getSeverityColor(event.severity) }}>
          {event.severity}
        </div>
      </div>

      <div className="certainty-row">
        {isConfirmed ? (
          <span className="certainty-badge confirmed">
            <Check className="icon-xs" /> Confirmed — direct inspection
          </span>
        ) : confidence != null ? (
          <span className="certainty-badge inferred">
            <span className="confidence-pct">{(confidence * 100).toFixed(0)}%</span> confidence — inferred
          </span>
        ) : null}
        <div className="event-body-inline">
          {exp.reference?.cwe && exp.reference.cwe !== 'N/A' && (
            <span className="meta-pill cwe-ref">{exp.reference.cwe}</span>
          )}
          {exp.reference?.owasp && exp.reference.owasp !== 'N/A' && (
            <span className="meta-pill owasp-ref">{exp.reference.owasp}</span>
          )}
        </div>
      </div>

      {exp.what && (
        <div className="explanation-section">
          <h4><AlertTriangle className="icon-sm" /> What</h4>
          <p>{exp.what}</p>
        </div>
      )}

      {exp.why_it_matters && (
        <div className="explanation-section">
          <h4><MessageCircle className="icon-sm" /> Why it matters</h4>
          <p>{exp.why_it_matters}</p>
        </div>
      )}

      {sourceInfo.where && (
        <div className="explanation-section">
          <h4><MapPin className="icon-sm" /> Where</h4>
          <div className="where-content">
            <span className={`source-badge source-${event.event_type}`}>
              {sourceInfo.icon} {sourceInfo.label}
            </span>
            <pre className="location-pre">{sourceInfo.where}</pre>
          </div>
        </div>
      )}

      {exp.confidence_note && (
        <div className={`explanation-section confidence-note-section ${isConfirmed ? 'confirmed-note' : 'inferred-note'}`}>
          <h4><BookOpen className="icon-sm" /> {isConfirmed ? 'Evidence' : 'Confidence'}</h4>
          <p className="confidence-note-text">{exp.confidence_note}</p>
        </div>
      )}

      {rem.guidance && (
        <div className="explanation-section">
          <h4><Wrench className="icon-sm" /> How to fix</h4>
          <p>{rem.guidance}</p>
          {rem.suggested_code_fix && (
            <div className="fix-section">
              <strong>Suggested code fix:</strong>
              <pre className="fix-code">{rem.suggested_code_fix}</pre>
              <p className="fix-disclaimer">This is a suggested fix and should be reviewed before applying.</p>
            </div>
          )}
        </div>
      )}

      {event.suggested_fix && !rem.suggested_code_fix && (
        <div className="explanation-section">
          <h4><Wrench className="icon-sm" /> Suggested Fix</h4>
          <pre className="fix-code">{event.suggested_fix}</pre>
          <p className="fix-disclaimer">This is a suggested fix and should be reviewed before applying.</p>
        </div>
      )}
    </div>
  );
};

export default FindingCard;
