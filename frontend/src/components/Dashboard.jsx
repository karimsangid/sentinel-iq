import React, { useState, useEffect } from 'react';
import { ShieldAlert, AlertTriangle, Activity, Server } from 'lucide-react';
import ThreatTimeline from './ThreatTimeline';
import SeverityChart from './SeverityChart';

// Mock data used when the backend is not connected
const MOCK_STATS = {
  total_logs: 1247,
  critical_count: 12,
  high_count: 45,
  medium_count: 128,
  low_count: 310,
  info_count: 752,
  anomalies_detected: 7,
  sources: ['webserver01', 'firewall01', 'DC01.corp.local', 'appserver01', 'dbserver01'],
  timeline: [],
};

const MOCK_TIMELINE = (() => {
  const data = [];
  const now = new Date();
  for (let i = 23; i >= 0; i--) {
    const time = new Date(now - i * 3600000).toISOString().slice(0, 13) + ':00';
    data.push({
      time,
      critical: Math.floor(Math.random() * 3),
      high: Math.floor(Math.random() * 8),
      medium: Math.floor(Math.random() * 15),
      low: Math.floor(Math.random() * 25),
      info: Math.floor(Math.random() * 50),
    });
  }
  return data;
})();

export default function Dashboard() {
  const [stats, setStats] = useState(MOCK_STATS);
  const [timeline, setTimeline] = useState(MOCK_TIMELINE);

  useEffect(() => {
    fetch('/api/stats')
      .then(r => r.json())
      .then(data => {
        if (data.total_logs > 0) {
          setStats(data);
          // Transform timeline data
          if (data.timeline && data.timeline.length > 0) {
            const grouped = {};
            data.timeline.forEach(({ time, severity, count }) => {
              if (!grouped[time]) grouped[time] = { time, critical: 0, high: 0, medium: 0, low: 0, info: 0 };
              grouped[time][severity] = count;
            });
            setTimeline(Object.values(grouped).sort((a, b) => a.time.localeCompare(b.time)));
          }
        }
      })
      .catch(() => { /* use mock data */ });
  }, []);

  const statCards = [
    { label: 'Total Logs', value: stats.total_logs.toLocaleString(), icon: Activity, color: 'var(--accent)' },
    { label: 'Critical Alerts', value: stats.critical_count, icon: ShieldAlert, color: 'var(--critical)' },
    { label: 'Anomalies', value: stats.anomalies_detected, icon: AlertTriangle, color: 'var(--high)' },
    { label: 'Sources', value: stats.sources.length, icon: Server, color: 'var(--success)' },
  ];

  return (
    <div className="dashboard">
      <div className="dashboard-header">
        <h2>Security Overview</h2>
        <span className="header-timestamp">Last updated: {new Date().toLocaleTimeString()}</span>
      </div>

      <div className="stats-grid">
        {statCards.map(({ label, value, icon: Icon, color }) => (
          <div className="stat-card" key={label}>
            <div className="stat-icon" style={{ color }}>
              <Icon size={24} />
            </div>
            <div className="stat-content">
              <span className="stat-value" style={{ color }}>{value}</span>
              <span className="stat-label">{label}</span>
            </div>
          </div>
        ))}
      </div>

      <div className="charts-grid">
        <div className="chart-card large">
          <h3>Threat Timeline (24h)</h3>
          <ThreatTimeline data={timeline} />
        </div>
        <div className="chart-card">
          <h3>Severity Distribution</h3>
          <SeverityChart stats={stats} />
        </div>
      </div>

      <div className="sources-card">
        <h3>Monitored Sources</h3>
        <div className="source-tags">
          {stats.sources.map(src => (
            <span key={src} className="source-tag">{src}</span>
          ))}
        </div>
      </div>
    </div>
  );
}
