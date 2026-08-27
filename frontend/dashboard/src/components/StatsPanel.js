import React from 'react';
import { BarChart3, Shield, AlertTriangle, TrendingUp } from 'lucide-react';

const StatsPanel = ({ stats, events }) => {
  const calculateStats = () => {
    if (!events || events.length === 0) {
      return {
        total: 0,
        network: 0,
        code: 0,
        critical: 0,
        high: 0,
        medium: 0,
        low: 0,
        info: 0,
        autoFlagged: 0,
        humanReview: 0,
        ignored: 0
      };
    }

    return {
      total: events.length,
      network: events.filter(e => e.event_type === 'network').length,
      code: events.filter(e => e.event_type === 'code').length,
      critical: events.filter(e => e.severity === 'critical').length,
      high: events.filter(e => e.severity === 'high').length,
      medium: events.filter(e => e.severity === 'medium').length,
      low: events.filter(e => e.severity === 'low').length,
      info: events.filter(e => e.severity === 'info').length,
      autoFlagged: events.filter(e => e.status === 'auto_flagged').length,
      humanReview: events.filter(e => e.status === 'human_review').length,
      ignored: events.filter(e => e.status === 'ignored').length
    };
  };

  const statsData = calculateStats();

  const StatCard = ({ icon: Icon, title, value, color }) => (
    <div className="stat-card">
      <Icon className="icon" style={{ color }} />
      <div className="stat-info">
        <span className="stat-value">{value}</span>
        <span className="stat-title">{title}</span>
      </div>
    </div>
  );

  return (
    <div className="stats-panel">
      <h2>
        <BarChart3 className="icon" />
        Statistics Dashboard
      </h2>

      <div className="stats-grid">
        <StatCard
          icon={Shield}
          title="Total Events"
          value={statsData.total}
          color="#3b82f6"
        />
        <StatCard
          icon={AlertTriangle}
          title="Network Events"
          value={statsData.network}
          color="#8b5cf6"
        />
        <StatCard
          icon={AlertTriangle}
          title="Code Events"
          value={statsData.code}
          color="#06b6d4"
        />
      </div>

      <div className="stats-section">
        <h3>By Severity</h3>
        <div className="severity-stats">
          <div className="severity-item critical">
            <span className="label">Critical</span>
            <span className="value">{statsData.critical}</span>
          </div>
          <div className="severity-item high">
            <span className="label">High</span>
            <span className="value">{statsData.high}</span>
          </div>
          <div className="severity-item medium">
            <span className="label">Medium</span>
            <span className="value">{statsData.medium}</span>
          </div>
          <div className="severity-item low">
            <span className="label">Low</span>
            <span className="value">{statsData.low}</span>
          </div>
          <div className="severity-item info">
            <span className="label">Info</span>
            <span className="value">{statsData.info}</span>
          </div>
        </div>
      </div>

      <div className="stats-section">
        <h3>By Status</h3>
        <div className="status-stats">
          <div className="status-item auto">
            <span className="label">Auto-Flagged</span>
            <span className="value">{statsData.autoFlagged}</span>
          </div>
          <div className="status-item review">
            <span className="label">Human Review</span>
            <span className="value">{statsData.humanReview}</span>
          </div>
          <div className="status-item ignored">
            <span className="label">Ignored</span>
            <span className="value">{statsData.ignored}</span>
          </div>
        </div>
      </div>

      <div className="stats-section">
        <h3>Recent Activity</h3>
        <div className="recent-events">
          {events.slice(0, 5).map((event, index) => (
            <div key={event._id || index} className="recent-event">
              <span className={`event-type-badge ${event.event_type}`}>
                {event.event_type}
              </span>
              <span className="event-prediction">{event.prediction}</span>
              <span className="event-confidence">
                {(event.confidence * 100).toFixed(1)}%
              </span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};

export default StatsPanel;
