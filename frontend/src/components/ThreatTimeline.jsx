import React from 'react';
import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
} from 'recharts';

const SEVERITY_COLORS = {
  critical: '#ef4444',
  high: '#f97316',
  medium: '#eab308',
  low: '#3b82f6',
  info: '#6b7280',
};

function CustomTooltip({ active, payload, label }) {
  if (!active || !payload) return null;
  return (
    <div style={{
      background: '#1a1a25',
      border: '1px solid #2a2a3a',
      borderRadius: 8,
      padding: '10px 14px',
      fontSize: 13,
    }}>
      <p style={{ color: '#a1a1aa', marginBottom: 6 }}>
        {label ? new Date(label).toLocaleString() : ''}
      </p>
      {payload.map((entry) => (
        <p key={entry.dataKey} style={{ color: entry.color, margin: '2px 0' }}>
          {entry.dataKey}: <strong>{entry.value}</strong>
        </p>
      ))}
    </div>
  );
}

export default function ThreatTimeline({ data }) {
  return (
    <div style={{ width: '100%', height: 300 }}>
      <ResponsiveContainer>
        <AreaChart data={data} margin={{ top: 5, right: 20, left: 0, bottom: 5 }}>
          <defs>
            {Object.entries(SEVERITY_COLORS).map(([key, color]) => (
              <linearGradient key={key} id={`grad-${key}`} x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%" stopColor={color} stopOpacity={0.4} />
                <stop offset="95%" stopColor={color} stopOpacity={0.05} />
              </linearGradient>
            ))}
          </defs>
          <CartesianGrid strokeDasharray="3 3" stroke="#1e1e2e" />
          <XAxis
            dataKey="time"
            tick={{ fill: '#71717a', fontSize: 11 }}
            tickFormatter={(v) => v ? new Date(v).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) : ''}
          />
          <YAxis tick={{ fill: '#71717a', fontSize: 11 }} />
          <Tooltip content={<CustomTooltip />} />
          <Area type="monotone" dataKey="info" stackId="1" stroke={SEVERITY_COLORS.info} fill="url(#grad-info)" />
          <Area type="monotone" dataKey="low" stackId="1" stroke={SEVERITY_COLORS.low} fill="url(#grad-low)" />
          <Area type="monotone" dataKey="medium" stackId="1" stroke={SEVERITY_COLORS.medium} fill="url(#grad-medium)" />
          <Area type="monotone" dataKey="high" stackId="1" stroke={SEVERITY_COLORS.high} fill="url(#grad-high)" />
          <Area type="monotone" dataKey="critical" stackId="1" stroke={SEVERITY_COLORS.critical} fill="url(#grad-critical)" />
        </AreaChart>
      </ResponsiveContainer>
    </div>
  );
}
