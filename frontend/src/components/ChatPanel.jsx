import React, { useState, useRef, useEffect } from 'react';
import { Send, Bot, User, Code } from 'lucide-react';

const SEVERITY_COLORS = {
  critical: '#ef4444',
  high: '#f97316',
  medium: '#eab308',
  low: '#3b82f6',
  info: '#6b7280',
};

export default function ChatPanel() {
  const [messages, setMessages] = useState([
    {
      role: 'assistant',
      content: 'Welcome to SentinelIQ. Ask me anything about your security logs. For example:\n\n- "Show failed SSH logins from last hour"\n- "What happened on 10.0.0.5?"\n- "Summarize today\'s critical alerts"\n- "Find port scan activity"',
    },
  ]);
  const [input, setInput] = useState('');
  const [loading, setLoading] = useState(false);
  const bottomRef = useRef(null);

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages]);

  const sendQuery = async () => {
    const query = input.trim();
    if (!query || loading) return;

    setInput('');
    setMessages(prev => [...prev, { role: 'user', content: query }]);
    setLoading(true);

    try {
      const res = await fetch('/api/query', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ query }),
      });

      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = await res.json();

      setMessages(prev => [...prev, {
        role: 'assistant',
        content: data.summary || `Found ${data.total_matches} result(s).`,
        filter: data.translated_filter,
        logs: data.logs?.slice(0, 10) || [],
      }]);
    } catch (err) {
      setMessages(prev => [...prev, {
        role: 'assistant',
        content: `Query failed: ${err.message}. Make sure the backend is running at localhost:8000.`,
      }]);
    } finally {
      setLoading(false);
    }
  };

  const handleKeyDown = (e) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      sendQuery();
    }
  };

  return (
    <div className="chat-page">
      <div className="chat-header">
        <h2>Chat with Your Logs</h2>
        <span className="chat-hint">Natural language queries powered by AI</span>
      </div>
      <div className="chat-messages">
        {messages.map((msg, i) => (
          <div key={i} className={`chat-message ${msg.role}`}>
            <div className="chat-avatar">
              {msg.role === 'assistant' ? <Bot size={18} /> : <User size={18} />}
            </div>
            <div className="chat-bubble">
              <p className="chat-text">{msg.content}</p>
              {msg.filter && (
                <div className="chat-filter">
                  <Code size={14} />
                  <pre>{msg.filter}</pre>
                </div>
              )}
              {msg.logs && msg.logs.length > 0 && (
                <div className="chat-results">
                  <table className="chat-log-table">
                    <thead>
                      <tr><th>Time</th><th>Sev</th><th>Source</th><th>Message</th></tr>
                    </thead>
                    <tbody>
                      {msg.logs.map((log, j) => (
                        <tr key={j}>
                          <td className="mono">{log.timestamp ? new Date(log.timestamp).toLocaleTimeString() : '-'}</td>
                          <td>
                            <span style={{ color: SEVERITY_COLORS[log.severity] || '#6b7280', fontWeight: 600 }}>
                              {log.severity}
                            </span>
                          </td>
                          <td className="mono">{log.source || '-'}</td>
                          <td className="mono">{log.message?.substring(0, 80)}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          </div>
        ))}
        {loading && (
          <div className="chat-message assistant">
            <div className="chat-avatar"><Bot size={18} /></div>
            <div className="chat-bubble"><span className="typing-dots">Analyzing</span></div>
          </div>
        )}
        <div ref={bottomRef} />
      </div>
      <div className="chat-input-area">
        <input
          type="text"
          value={input}
          onChange={e => setInput(e.target.value)}
          onKeyDown={handleKeyDown}
          placeholder="Ask about your security logs..."
          className="chat-input"
          disabled={loading}
        />
        <button onClick={sendQuery} disabled={loading || !input.trim()} className="chat-send-btn">
          <Send size={18} />
        </button>
      </div>
    </div>
  );
}
