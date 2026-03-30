import React, { useState, useEffect, useRef } from 'react';

const SEVERITY_STYLES = {
  critical: { bg: '#ef444420', color: '#ef4444', border: '#ef444440' },
  high:     { bg: '#f9731620', color: '#f97316', border: '#f9731640' },
  medium:   { bg: '#eab30820', color: '#eab308', border: '#eab30840' },
  low:      { bg: '#3b82f620', color: '#3b82f6', border: '#3b82f640' },
  info:     { bg: '#6b728020', color: '#6b7280', border: '#6b728040' },
};

// Mock logs for when backend is not connected
const MOCK_LOGS = [
  { id: '1', timestamp: '2025-01-15T08:23:01', source: 'sshd', severity: 'high', message: 'Failed password for invalid user admin from 192.168.1.100 port 52341 ssh2' },
  { id: '2', timestamp: '2025-01-15T08:23:03', source: 'sshd', severity: 'high', message: 'Failed password for invalid user admin from 192.168.1.100 port 52342 ssh2' },
  { id: '3', timestamp: '2025-01-15T08:24:15', source: 'sshd', severity: 'info', message: 'Accepted publickey for deploy from 10.0.0.50 port 44312 ssh2' },
  { id: '4', timestamp: '2025-01-15T08:45:12', source: 'kernel', severity: 'medium', message: '[UFW BLOCK] IN=eth0 SRC=203.0.113.45 DST=10.0.0.1 PROTO=TCP DPT=22' },
  { id: '5', timestamp: '2025-01-15T09:00:00', source: 'mysqld', severity: 'medium', message: 'Warning: Aborted connection 1523 to db: production (Got timeout reading communication packets)' },
  { id: '6', timestamp: '2025-01-15T09:45:30', source: 'nagios', severity: 'critical', message: 'SERVICE ALERT: webserver01;HTTP;CRITICAL;HARD;3;HTTP CRITICAL: HTTP/1.1 503 Service Temporarily Unavailable' },
  { id: '7', timestamp: '2025-01-15T09:46:00', source: 'nginx', severity: 'medium', message: '198.51.100.23 - - "POST /admin/login HTTP/1.1" 401 52 "-" "Mozilla/5.0"' },
  { id: '8', timestamp: '2025-01-15T10:00:00', source: 'mysqld', severity: 'high', message: 'InnoDB: Warning: disk space is running low on /var/lib/mysql' },
  { id: '9', timestamp: '2025-01-15T10:15:00', source: 'dockerd', severity: 'info', message: 'container app-api started successfully' },
  { id: '10', timestamp: '2025-01-15T11:00:00', source: 'sshd', severity: 'info', message: 'Accepted password for admin from 10.0.0.2 port 55123 ssh2' },
  { id: '11', timestamp: '2025-01-15T11:05:00', source: 'sudo', severity: 'low', message: 'admin : TTY=pts/0 ; PWD=/home/admin ; USER=root ; COMMAND=/bin/systemctl restart nginx' },
  { id: '12', timestamp: '2025-01-15T11:10:00', source: 'nagios', severity: 'info', message: 'SERVICE ALERT: webserver01;HTTP;OK;HARD;1;HTTP OK: HTTP/1.1 200 OK' },
];

const SEVERITIES = ['all', 'critical', 'high', 'medium', 'low', 'info'];

export default function LogStream() {
  const [logs, setLogs] = useState(MOCK_LOGS);
  const [filter, setFilter] = useState('all');
  const [expanded, setExpanded] = useState(null);
  const [wsConnected, setWsConnected] = useState(false);
  const scrollRef = useRef(null);

  useEffect(() => {
    // Try to fetch logs from API
    fetch('/api/logs?limit=100')
      .then(r => r.json())
      .then(data => {
        if (Array.isArray(data) && data.length > 0) {
          setLogs(data);
        }
      })
      .catch(() => {});

    // Try WebSocket connection
    let ws;
    try {
      const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
      const wsUrl = `${protocol}//${window.location.host}/ws/logs`;
      ws = new WebSocket(wsUrl);
      ws.onopen = () => setWsConnected(true);
      ws.onclose = () => setWsConnected(false);
      ws.onmessage = (event) => {
        try {
          const msg = JSON.parse(event.data);
          if (msg.type === 'log') {
            setLogs(prev => [msg.data, ...prev].slice(0, 500));
          }
        } catch {}
      };
    } catch {}

    return () => { if (ws) ws.close(); };
  }, []);

  const filtered = filter === 'all' ? logs : logs.filter(l => l.severity === filter);

  return (
    <div className="log-stream-page">
      <div className="log-stream-header">
        <h2>Log Stream</h2>
        <div className="log-stream-controls">
          <span className={`ws-status ${wsConnected ? 'connected' : ''}`}>
            {wsConnected ? 'Live' : 'Offline'}
          </span>
          <select value={filter} onChange={e => setFilter(e.target.value)} className="severity-filter">
            {SEVERITIES.map(s => (
              <option key={s} value={s}>{s === 'all' ? 'All Severities' : s.charAt(0).toUpperCase() + s.slice(1)}</option>
            ))}
          </select>
        </div>
      </div>
      <div className="log-table-wrapper" ref={scrollRef}>
        <table className="log-table">
          <thead>
            <tr>
              <th style={{ width: 170 }}>Timestamp</th>
              <th style={{ width: 120 }}>Source</th>
              <th style={{ width: 90 }}>Severity</th>
              <th>Message</th>
            </tr>
          </thead>
          <tbody>
            {filtered.map(log => {
              const sev = SEVERITY_STYLES[log.severity] || SEVERITY_STYLES.info;
              return (
                <React.Fragment key={log.id}>
                  <tr
                    className="log-row"
                    onClick={() => setExpanded(expanded === log.id ? null : log.id)}
                    style={{ cursor: 'pointer' }}
                  >
                    <td className="mono">{log.timestamp ? new Date(log.timestamp).toLocaleString() : '-'}</td>
                    <td className="mono">{log.source || '-'}</td>
                    <td>
                      <span className="severity-badge" style={{ background: sev.bg, color: sev.color, borderColor: sev.border }}>
                        {log.severity}
                      </span>
                    </td>
                    <td className="mono message-cell">{log.message?.substring(0, 120)}{log.message?.length > 120 ? '...' : ''}</td>
                  </tr>
                  {expanded === log.id && (
                    <tr className="log-expanded">
                      <td colSpan={4}>
                        <pre className="log-detail">{JSON.stringify(log, null, 2)}</pre>
                      </td>
                    </tr>
                  )}
                </React.Fragment>
              );
            })}
          </tbody>
        </table>
        {filtered.length === 0 && (
          <p style={{ textAlign: 'center', padding: 40, color: '#71717a' }}>No logs match the current filter.</p>
        )}
      </div>
    </div>
  );
}
