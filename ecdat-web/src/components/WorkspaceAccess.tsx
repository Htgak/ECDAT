import { readJson } from '../api/response';
import { ThemeToggle } from './ThemeToggle';
import { useEffect, useState, type ReactNode, type FormEvent } from 'react';

import { UserContext, type WorkspaceUser } from './WorkspaceUserContext';

export function WorkspaceAccess({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<WorkspaceUser | null>(null);
  const [loading, setLoading] = useState(true);
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  useEffect(() => {
    let active = true;
    const check = async () => {
      try {
        const response = await fetch('/api/v1/session');
        if (!response.ok) throw new Error();
        const state = await readJson(response);
        if (active) { setUser(state.authenticated ? state.user : null); setError(''); }
      } catch { if (active) { setUser(null); setError('Cannot connect to the workspace. Check the backend and reload.'); } }
      finally { if (active) setLoading(false); }
    };
    void check();
    const timer = setInterval(check, 30000);
    const expired = () => { setUser(null); setPassword(''); };
    window.addEventListener('workspace-auth-expired', expired);
    return () => { active = false; clearInterval(timer); window.removeEventListener('workspace-auth-expired', expired); };
  }, []);
  async function login(event: FormEvent) {
    event.preventDefault(); setBusy(true); setError('');
    try {
      const response = await fetch('/api/v1/session', {method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username,password})});
      const state = await readJson(response);
      if (!response.ok) throw new Error(typeof state.detail === 'string' ? state.detail : 'Sign-in failed. Check your username and password.');
      setUser(state.user); setPassword('');
    } catch (e) { setError(e instanceof Error ? e.message : 'Sign-in failed.'); }
    finally { setBusy(false); }
  }
  async function logout() {
    setBusy(true);
    try {
      const response = await fetch('/api/v1/session',{method:'DELETE'});
      if (!response.ok) throw new Error();
      setUser(null); setPassword(''); setError('');
    } catch { setError('Sign-out failed. Please retry.'); }
    finally { setBusy(false); }
  }
  if (loading) return <main className="access-panel" role="status">Connecting to workspace...</main>;
  if (!user) return <main className="access-panel">
    <div className="access-theme"><ThemeToggle /></div>
    <img src="/ecdat-logo.png" alt="ECDAT" style={{width:48,height:48}}/>
    <h1>Sign in to ECDAT</h1><p>Your scans and reports stay in your account.</p>
    {error && <p className="error-banner" role="alert">{error}</p>}
    <form onSubmit={login}>
      <label htmlFor="username">Username</label><input id="username" autoComplete="username" autoCapitalize="none" value={username} onChange={e=>setUsername(e.target.value)} required minLength={3} maxLength={80}/>
      <label htmlFor="password">Password</label><input id="password" type="password" autoComplete="current-password" value={password} onChange={e=>setPassword(e.target.value)} required maxLength={128}/>
      <button className="btn btn-primary" disabled={busy} type="submit">{busy ? 'Signing in...' : 'Sign in'}</button>
    </form><p className="text-muted">Sign in with your account. Contact your administrator for access.</p>
  </main>;
  return <UserContext.Provider value={user}>{children}{error && <p role="alert" className="error-banner">{error}</p>}<button className="btn btn-secondary session-control" disabled={busy} onClick={()=>void logout()}>Sign out ({user.username})</button></UserContext.Provider>;
}
