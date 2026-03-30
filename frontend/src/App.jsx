import React, { useState } from 'react';
import { Shield, LayoutDashboard, MessageSquare, Upload, Activity } from 'lucide-react';
import Dashboard from './components/Dashboard';
import ChatPanel from './components/ChatPanel';
import UploadPanel from './components/UploadPanel';
import LogStream from './components/LogStream';
import './styles/dashboard.css';

const NAV_ITEMS = [
  { id: 'dashboard', label: 'Dashboard', icon: LayoutDashboard },
  { id: 'logs', label: 'Log Stream', icon: Activity },
  { id: 'chat', label: 'Chat Query', icon: MessageSquare },
  { id: 'upload', label: 'Upload', icon: Upload },
];

export default function App() {
  const [activeView, setActiveView] = useState('dashboard');

  const renderContent = () => {
    switch (activeView) {
      case 'dashboard': return <Dashboard />;
      case 'logs': return <LogStream />;
      case 'chat': return <ChatPanel />;
      case 'upload': return <UploadPanel />;
      default: return <Dashboard />;
    }
  };

  return (
    <div className="app-layout">
      <aside className="sidebar">
        <div className="sidebar-brand">
          <Shield size={28} className="brand-icon" />
          <div>
            <h1 className="brand-title">SentinelIQ</h1>
            <span className="brand-subtitle">by Hummus Development</span>
          </div>
        </div>
        <nav className="sidebar-nav">
          {NAV_ITEMS.map(({ id, label, icon: Icon }) => (
            <button
              key={id}
              className={`nav-item ${activeView === id ? 'active' : ''}`}
              onClick={() => setActiveView(id)}
            >
              <Icon size={18} />
              <span>{label}</span>
            </button>
          ))}
        </nav>
        <div className="sidebar-footer">
          <div className="status-indicator">
            <span className="status-dot online" />
            <span>System Online</span>
          </div>
          <span className="version">v0.1.0 — Hummus Development LLC</span>
        </div>
      </aside>
      <main className="main-content">
        {renderContent()}
      </main>
    </div>
  );
}
