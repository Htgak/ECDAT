import { useWorkspaceUser } from '../WorkspaceUserContext';
import { ThemeToggle } from '../ThemeToggle';
import { useState } from 'react';
import { useLocation, useNavigate } from 'react-router-dom';
import { Plus, MagnifyingGlass, List, X } from '@phosphor-icons/react';
interface NavbarProps { onOpenScanModal: () => void; menuOpen: boolean; onToggleMenu: () => void; }
export function Navbar({ onOpenScanModal, menuOpen, onToggleMenu }: NavbarProps) {
  const admin = useWorkspaceUser()?.role === 'admin';
  const [query, setQuery] = useState('');
  const navigate = useNavigate();
  const location = useLocation();
  const titles: Record<string, string> = { admin: 'Users', assets: 'Crypto inventory', scans: 'Discovery scans', policies: 'Policy compliance', advisories: 'PQC advisories', exports: 'Exports & proof', audit: 'Audit trail' };
  return <header className="app-header">
    <div className="header-location"><button className="btn btn-ghost mobile-menu" onClick={onToggleMenu} aria-label={menuOpen ? 'Close navigation' : 'Open navigation'} aria-expanded={menuOpen}>{menuOpen ? <X size={21}/> : <List size={21}/>}</button><span className="text-dim">{location.pathname.startsWith('/admin') ? 'Administration' : 'Workspace'}</span><span className="text-dim">/</span><span>{titles[location.pathname.split('/')[1]] || 'Overview'}</span></div>
    <div className="header-actions"><ThemeToggle />{!admin && <><form className="global-search" role="search" onSubmit={e => { e.preventDefault(); navigate(`/assets?q=${encodeURIComponent(query.trim())}`); }}><MagnifyingGlass size={17}/><input aria-label="Search crypto inventory" placeholder="Search inventory..." value={query} onChange={e => setQuery(e.target.value)}/><kbd>Enter</kbd></form><button className="btn btn-primary" onClick={onOpenScanModal}><Plus size={17} weight="bold"/>New scan</button></>}</div>
  </header>;
}
