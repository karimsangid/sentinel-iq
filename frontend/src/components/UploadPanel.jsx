import React, { useState, useRef } from 'react';
import { Upload, FileText, CheckCircle, XCircle } from 'lucide-react';

const ACCEPTED_EXTENSIONS = ['.log', '.json', '.csv', '.txt', '.cef'];

export default function UploadPanel() {
  const [isDragging, setIsDragging] = useState(false);
  const [uploads, setUploads] = useState([]);
  const fileInputRef = useRef(null);

  const handleFiles = async (files) => {
    for (const file of files) {
      const ext = '.' + file.name.split('.').pop().toLowerCase();
      if (!ACCEPTED_EXTENSIONS.includes(ext)) {
        setUploads(prev => [...prev, { name: file.name, status: 'error', message: 'Unsupported file type' }]);
        continue;
      }

      const entry = { name: file.name, status: 'uploading', message: 'Uploading...' };
      setUploads(prev => [...prev, entry]);

      try {
        const formData = new FormData();
        formData.append('file', file);

        const res = await fetch('/api/ingest/file', { method: 'POST', body: formData });

        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const data = await res.json();

        setUploads(prev =>
          prev.map(u =>
            u.name === file.name && u.status === 'uploading'
              ? {
                  ...u,
                  status: 'success',
                  message: `Parsed ${data.parsed} of ${data.total_lines} lines (${data.log_type})`,
                  result: data,
                }
              : u
          )
        );
      } catch (err) {
        setUploads(prev =>
          prev.map(u =>
            u.name === file.name && u.status === 'uploading'
              ? { ...u, status: 'error', message: `Upload failed: ${err.message}` }
              : u
          )
        );
      }
    }
  };

  const onDrop = (e) => {
    e.preventDefault();
    setIsDragging(false);
    if (e.dataTransfer.files.length > 0) {
      handleFiles(Array.from(e.dataTransfer.files));
    }
  };

  const onDragOver = (e) => { e.preventDefault(); setIsDragging(true); };
  const onDragLeave = () => setIsDragging(false);

  return (
    <div className="upload-page">
      <div className="upload-header">
        <h2>Upload Log Files</h2>
        <span className="upload-hint">Supported formats: .log, .json, .csv, .txt, .cef</span>
      </div>

      <div
        className={`upload-zone ${isDragging ? 'dragging' : ''}`}
        onDrop={onDrop}
        onDragOver={onDragOver}
        onDragLeave={onDragLeave}
        onClick={() => fileInputRef.current?.click()}
      >
        <Upload size={48} className="upload-icon" />
        <p className="upload-text">Drag & drop log files here</p>
        <p className="upload-subtext">or click to browse</p>
        <input
          ref={fileInputRef}
          type="file"
          multiple
          accept=".log,.json,.csv,.txt,.cef"
          style={{ display: 'none' }}
          onChange={(e) => handleFiles(Array.from(e.target.files))}
        />
      </div>

      {uploads.length > 0 && (
        <div className="upload-results">
          <h3>Upload History</h3>
          {uploads.map((u, i) => (
            <div key={i} className={`upload-item ${u.status}`}>
              <div className="upload-item-icon">
                {u.status === 'success' && <CheckCircle size={18} />}
                {u.status === 'error' && <XCircle size={18} />}
                {u.status === 'uploading' && <FileText size={18} className="spinning" />}
              </div>
              <div className="upload-item-info">
                <span className="upload-item-name">{u.name}</span>
                <span className="upload-item-message">{u.message}</span>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
