import React, { useMemo, useState } from 'react';
import Notification from '../components/Notification';
import { askHelpCenter } from '../api/apiClient';
import './HelpCenter.css';

const HelpCenter = () => {
  const [notification, setNotification] = useState(null);
  const [messages, setMessages] = useState(() => ([
    {
      role: 'assistant',
      content: 'Ask me how to do something in the platform (I answer from the User Flows PDF). Example: "How do I schedule a scan?"',
      sources: [],
    },
  ]));
  const [input, setInput] = useState('');
  const [sending, setSending] = useState(false);

  const canSend = useMemo(() => input.trim().length > 0 && !sending, [input, sending]);

  const send = async () => {
    const q = input.trim();
    if (!q || sending) return;
    setSending(true);
    setInput('');
    setMessages((prev) => [...prev, { role: 'user', content: q }]);
    try {
      const res = await askHelpCenter(q, 3);
      setMessages((prev) => [
        ...prev,
        { role: 'assistant', content: res?.answer || 'No answer returned.', sources: [] },
      ]);
    } catch (err) {
      setNotification({ message: err.message, type: 'error' });
      setMessages((prev) => [
        ...prev,
        { role: 'assistant', content: 'I couldn’t answer that right now. Please try again.', sources: [] },
      ]);
    } finally {
      setSending(false);
    }
  };

  return (
    <div className="help-page">
      {notification && (
        <Notification
          message={notification.message}
          type={notification.type}
          onClose={() => setNotification(null)}
          duration={5000}
        />
      )}

      <div className="help-header">
        <h1 className="page-title">HELP CENTER</h1>
        <div className="help-subtitle">Ask questions about workflows. Answers are sourced from the User Flows PDF.</div>
      </div>

      <div className="help-card">
        <div className="help-chat">
          {messages.map((m, idx) => (
            <div key={idx} className={`help-msg ${m.role === 'user' ? 'user' : 'assistant'}`}>
              <div className="help-bubble">
                <div className="help-text">{m.content}</div>
              </div>
            </div>
          ))}
        </div>

        <div className="help-input-row">
          <input
            className="help-input"
            value={input}
            onChange={(e) => setInput(e.target.value)}
            placeholder='Ask: "How do I run a live scan?"'
            onKeyDown={(e) => {
              if (e.key === 'Enter') send();
            }}
            disabled={sending}
          />
          <button className="btn-primary" type="button" onClick={send} disabled={!canSend}>
            {sending ? 'Answering…' : 'Ask'}
          </button>
        </div>
      </div>
    </div>
  );
};

export default HelpCenter;

