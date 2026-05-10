import React from 'react';
import { PieChart, Pie, Cell, Tooltip, ResponsiveContainer, Legend } from 'recharts';

const COLORS = {
  Critical: '#ef4444',
  High: '#f97316',
  Medium: '#eab308',
  Low: '#3b82f6',
  Info: '#6b7280',
};

function CustomTooltip({ active, payload }) {
  if (!active || !payload || !payload.length) return null;
  const { name, value } = payload[0];
  return (
    <div style={{
      background: '#1a1a25',
      border: '1px solid #2a2a3a',
      borderRadius: 8,
      padding: '8px 12px',
      fontSize: 13,
    }}>
      <span style={{ color: COLORS[name] || '#e4e4e7' }}>
        {name}: <strong>{value}</strong>
      </span>
    </div>
  );
}

export default function SeverityChart({ stats }) {
  const data = [
    { name: 'Critical', value: stats.critical_count },
    { name: 'High', value: stats.high_count },
    { name: 'Medium', value: stats.medium_count },
    { name: 'Low', value: stats.low_count },
    { name: 'Info', value: stats.info_count },
  ].filter(d => d.value > 0);

  if (data.length === 0) {
    return <p style={{ color: '#71717a', textAlign: 'center', paddingTop: 60 }}>No data yet</p>;
  }

  return (
    <div style={{ width: '100%', height: 300 }}>
      <ResponsiveContainer>
        <PieChart>
          <Pie
            data={data}
            cx="50%"
            cy="50%"
            innerRadius={60}
            outerRadius={100}
            paddingAngle={3}
            dataKey="value"
          >
            {data.map((entry) => (
              <Cell key={entry.name} fill={COLORS[entry.name]} stroke="none" />
            ))}
          </Pie>
          <Tooltip content={<CustomTooltip />} />
          <Legend
            wrapperStyle={{ fontSize: 12, color: '#a1a1aa' }}
            formatter={(value) => <span style={{ color: '#a1a1aa' }}>{value}</span>}
          />
        </PieChart>
      </ResponsiveContainer>
    </div>
  );
}
