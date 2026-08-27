import React from 'react';
import { Shield, Trash2 } from 'lucide-react';
import FindingCard from './FindingCard';

const ThreatFeed = ({ events, onClear }) => {
  return (
    <div className="threat-feed">
      <div className="feed-header">
        <h2>Live Threat Feed</h2>
        {events.length > 0 && (
          <button onClick={onClear} className="clear-btn">
            <Trash2 className="icon-sm" /> Clear
          </button>
        )}
      </div>

      {events.length === 0 ? (
        <div className="no-events">
          <Shield className="icon" />
          <p>No threats detected yet. Waiting for incoming events...</p>
        </div>
      ) : (
        <div className="events-list">
          {events.map((event, index) => (
            <FindingCard key={event._id || index} event={event} />
          ))}
        </div>
      )}
    </div>
  );
};

export default ThreatFeed;
