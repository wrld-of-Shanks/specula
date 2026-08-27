import React, { useState, useEffect, useRef } from 'react';
import ThreatFeedSidebar from './components/ThreatFeedSidebar';
import UnifiedScanner from './components/UnifiedScanner';
import StatsBar from './components/StatsBar';
import { useWebSocket } from './services/websocket';
import { fetchEvents, fetchStats } from './services/api';

function App() {
  const [events, setEvents] = useState([]);
  const [stats, setStats] = useState(null);
  const [loading, setLoading] = useState(true);
  const [feedPaused, setFeedPaused] = useState(false);
  const pausedRef = useRef(false);

  const wsUrl = process.env.REACT_APP_WS_URL || `${window.location.protocol === 'https:' ? 'wss:' : 'ws:'}//${window.location.host}/ws`;
  const ws = useWebSocket(wsUrl);

  useEffect(() => {
    loadInitialData();
  }, []);

  useEffect(() => {
    pausedRef.current = feedPaused;
  }, [feedPaused]);

  useEffect(() => {
    if (ws) {
      ws.onmessage = (event) => {
        const data = JSON.parse(event.data);
        if (data.type === 'new_event') {
          if (pausedRef.current) return;
          setEvents(prev => {
            const incoming = data.data;
            const id = incoming?._id;
            if (id && prev.some(e => e._id === id)) return prev;
            return [incoming, ...prev].slice(0, 200);
          });
        }
      };
    }
  }, [ws]);

  const loadInitialData = async () => {
    try {
      const clearedAt = localStorage.getItem('sentinel_feed_cleared_at');
      const params = clearedAt ? { since: clearedAt } : { since: new Date().toISOString() };
      const [eventsData, statsData] = await Promise.all([
        fetchEvents(params),
        fetchStats()
      ]);
      setEvents(eventsData);
      setStats(statsData);
    } catch (error) {
      console.error('Failed to load data:', error);
    } finally {
      setLoading(false);
    }
  };

  const clearEvents = () => {
    localStorage.setItem('sentinel_feed_cleared_at', new Date().toISOString());
    setEvents([]);
    setFeedPaused(true);
  };

  const resumeFeed = () => {
    setFeedPaused(false);
  };

  return (
    <>
    <div className="scanlines" />
    <div className="app-layout">
      <aside className="sidebar">
        <div className="sidebar-header">
          <h1 className="sidebar-brand">
            Specula
          </h1>
          <p className="sidebar-subtitle">Security Monitor</p>
        </div>
        <ThreatFeedSidebar events={events} onClear={clearEvents} paused={feedPaused} />
      </aside>

      <main className="main-content">
        <header className="topbar">
          <div className="topbar-left">
            <h2 className="topbar-title">HORUS (Security Scanner)</h2>
          </div>
          <div className="topbar-right">
            {feedPaused && (
              <span className="feed-paused-badge">Feed paused</span>
            )}
            <span className={`ws-status ${ws ? 'connected' : ''}`}>
              <span className="ws-dot" />
              {ws ? 'Live' : 'Offline'}
            </span>
          </div>
        </header>

        {loading ? (
          <div className="loading-full">
            <div className="loading-spinner" />
            <span>Loading...</span>
          </div>
        ) : (
          <div className="main-scroll">
            <StatsBar events={events} />
            <UnifiedScanner onResumeFeed={resumeFeed} />
          </div>
        )}
      </main>
    </div>
    </>
  );
}

export default App;
