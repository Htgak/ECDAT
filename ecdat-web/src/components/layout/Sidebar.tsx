import { useWorkspaceUser } from '../WorkspaceUserContext';
import { NavLink, Link } from 'react-router-dom';
import { ChartPie, ShieldWarning, Scan, ShieldCheck, Lightbulb, DownloadSimple } from '@phosphor-icons/react';
const groups = [
  {title:'WORKSPACE', items:[{to:'/',label:'Overview',icon:ChartPie},{to:'/assets',label:'Crypto inventory',icon:ShieldWarning},{to:'/scans',label:'Discovery scans',icon:Scan}]},
  {title:'GOVERNANCE', items:[{to:'/policies',label:'Policy compliance',icon:ShieldCheck},{to:'/advisories',label:'PQC advisories',icon:Lightbulb},{to:'/exports',label:'Exports & CBOM',icon:DownloadSimple}]},
];
export function Sidebar() {
  const user = useWorkspaceUser();
  return <aside className="app-sidebar" aria-label="Workspace navigation">
    <Link to="/" className="brand"><img className="brand-custom" src="/ecdat-logo.png" alt=""/><span><strong>ECDAT</strong><small>Cryptographic discovery</small></span></Link>
    <div className="workspace-label"><div>{user?.role === 'admin' ? 'Administration' : 'Enterprise workspace'}<small>{user?.role === 'admin' ? 'Manage user accounts.' : 'Discover. Assess. Transition.'}</small></div></div>
    <nav className="primary-nav" aria-label="Main navigation">{(user?.role === "admin" ? [] : groups).map(group => <div key={group.title}><p className="nav-caption nav-section">{group.title}</p>{group.items.map(({to,label,icon:Icon}) => <NavLink key={to} to={to} end={to === '/'} className={({isActive}) => `nav-link ${isActive ? 'active' : ''}`}><Icon size={19}/><span>{label}</span></NavLink>)}</div>)}{user?.role === "admin" && <div><p className="nav-caption nav-section">ADMINISTRATION</p><NavLink to="/admin/users" className={({isActive}) => `nav-link ${isActive ? "active" : ""}`}><ShieldCheck size={19}/><span>Users</span></NavLink></div>}</nav>
    <div className="sidebar-footer">Enterprise Cryptographic Discovery<br/> & Analysis Tool</div>
  </aside>;
}
