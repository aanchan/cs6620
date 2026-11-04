import { useEffect, useState } from 'react';
import './App.css';

export default function App() {
  // Hard-coded for now; replace with real auth later.
  const [email] = useState('dev@example.com');

  const [url, setUrl] = useState('');
  const [frequency, setFrequency] = useState('daily');
  const [targets, setTargets] = useState([]);
  const [error, setError] = useState('');
  const [submitting, setSubmitting] = useState(false);

  async function loadTargets() {
    try {
      const res = await fetch(`/targets?ownerId=${encodeURIComponent(email)}`);
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || 'Failed to load targets.');
      setTargets(data);
    } catch (err) {
      setError(err.message);
    }
  }

  useEffect(() => {
    loadTargets();
  }, [email]);

  async function handleSubmit(e) {
    e.preventDefault();
    setError('');
    setSubmitting(true);
    try {
      const res = await fetch('/targets', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url, frequency, email })
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || 'Failed to register target.');
      setUrl('');
      await loadTargets();
    } catch (err) {
      setError(err.message);
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <main className="app">
      <header className="header">
        <h1>Pentest Scheduler</h1>
        <span className="user-chip">{email}</span>
      </header>

      <section className="card">
        <h2>Register a target</h2>
        <form className="form" onSubmit={handleSubmit}>
          <input
            type="url"
            placeholder="https://api.example.com"
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            required
          />
          <select value={frequency} onChange={(e) => setFrequency(e.target.value)}>
            <option value="hourly">Hourly</option>
            <option value="daily">Daily</option>
            <option value="weekly">Weekly</option>
          </select>
          <button className="btn" type="submit" disabled={submitting}>
            {submitting ? 'Adding…' : 'Add target'}
          </button>
        </form>
        {error && <div className="error">{error}</div>}
      </section>

      <section className="card">
        <h2>Your targets ({targets.length})</h2>
        {targets.length === 0 ? (
          <p className="empty">No targets yet. Add one above.</p>
        ) : (
          <ul className="target-list">
            {targets.map((t) => (
              <li className="target" key={t.targetId}>
                <div>
                  <div className="target-url">{t.url}</div>
                  <div className="target-meta">
                    Next run: {new Date(t.nextRunAt).toLocaleString()}
                  </div>
                </div>
                <div className="badges">
                  <span className="badge">{t.frequency}</span>
                  <span className={`badge ${t.status}`}>{t.status}</span>
                </div>
              </li>
            ))}
          </ul>
        )}
      </section>
    </main>
  );
}
