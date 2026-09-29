import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { ArrowRight, ArrowUpRight, ArrowClockwise, Cube, Scan as ScanIcon, WarningCircle, ShieldCheck, DownloadSimple } from '@phosphor-icons/react';
import { apiClient } from '../api/client';
import { Badge } from '../components/ui/Badge';
import type { Asset, Scan } from '../api/types';

export function DashboardPage() {
  const [assets, setAssets] = useState<Asset[]>([]);
  const [scans, setScans] = useState<Scan[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [updated, setUpdated] = useState<Date | null>(null);
  const [refresh, setRefresh] = useState(0);
  useEffect(() => {
    let alive = true;
    let busy = false;
    async function load() {
      if (busy) return;
      busy = true;
      try {
        const [items, runs] = await Promise.all([apiClient.getAllAssets(), apiClient.getScans()]);
        if (alive) { setAssets(items); setScans(runs); setError(''); setUpdated(new Date()); }
      } catch { if (alive) setError('Unable to refresh the workspace. Check the API connection and try again.'); }
      finally { busy = false; if (alive) setLoading(false); }
    }
    void load();
    const timer = setInterval(load, 30000);
    return () => { alive = false; clearInterval(timer); };
  }, [refresh]);
  const urgent = assets.filter(a => a.mosca_verdict === 'act_now').sort((a,b) => (b.qars_score ?? -1) - (a.qars_score ?? -1));
  const safe = assets.filter(a => a.mosca_verdict === 'safe').length;
  const monitor = assets.filter(a => a.mosca_verdict === 'monitor').length;
  const unknown = assets.length - urgent.length - safe - monitor;
  const completed = scans.filter(s => s.is_complete || s.status === 'COMPLETED').length;
  const recent = [...scans].sort((a,b) => Date.parse(b.created_at) - Date.parse(a.created_at)).slice(0,4);
  const groups = [{name: 'Act now', count: urgent.length, color: 'var(--color-act-now)', filter: 'act_now'}, {name: 'Monitor', count: monitor, color: 'var(--color-monitor)', filter: 'monitor'}, {name: 'Within horizon', count: safe, color: 'var(--color-safe)', filter: 'safe'}, {name: 'Not assessed', count: unknown, color: 'var(--text-dim)', filter: ''}];
  const metrics = [{label: 'Discovered assets', value: assets.length, detail: 'Across your cryptographic estate', icon: Cube, to: '/assets'}, {label: 'Require action', value: urgent.length, detail: 'Prioritize for migration review', icon: WarningCircle, to: '/assets?risk=act_now'}, {label: 'Within selected horizon', value: safe, detail: 'Based on current Mosca assessment', icon: ShieldCheck, to: '/assets?risk=safe'}, {label: 'Completed scans', value: completed, detail: `${scans.length} total discovery runs`, icon: ScanIcon, to: '/scans'}];
  return <div className="page-container overview">
    <div className="page-header"><div><div className="eyebrow">CRYPTOGRAPHIC POSTURE</div><h1 className="page-title">Your estate, in focus.</h1><p className="page-subtitle">Deterministic, evidence-first cryptographic discovery and post-quantum migration planning.</p></div><div className="page-actions"><button className="btn btn-secondary" onClick={() => setRefresh(n => n+1)} aria-label="Refresh overview"><ArrowClockwise size={16}/></button><Link className="btn btn-secondary" to="/exports"><DownloadSimple size={16}/>Export reports</Link></div></div>
    {error && <div className="error-banner" role="alert"><WarningCircle size={20}/><span>{error}{updated && ' Showing the last successful update.'}</span><button className="btn btn-secondary" onClick={() => setRefresh(n => n+1)}>Retry</button></div>}
    <section className="metric-strip" aria-label="Estate metrics" aria-busy={loading}>{metrics.map(({label,value,detail,icon: Icon,to}) => <Link className="metric" key={label} to={to}><div className="metric-heading">{label}<Icon size={19}/></div>{loading ? <div className="skeleton metric-skeleton"/> : <div className="metric-number">{updated ? value.toLocaleString() : '\u2014'}<ArrowUpRight size={19}/></div>}<p>{detail}</p></Link>)}</section>
    <div className="overview-grid"><section className="panel attention-panel"><div className="section-heading"><div><span className="eyebrow">PRIORITY QUEUE</span><h2>Start where it matters.</h2></div><span className="square-icon"><WarningCircle size={25}/></span></div><p className="attention-copy">{!updated ? 'Your latest discovery results will appear here.' : urgent.length ? `${urgent.length} cryptographic ${urgent.length === 1 ? 'asset needs' : 'assets need'} attention. Review the evidence and plan a transition before the risk horizon closes.` : assets.length ? 'No assets currently have an act-now verdict. Keep discovery running to track changes in your estate.' : 'Your estate is ready to discover. Start a scan to identify algorithms, keys, and certificates.'}</p><Link to={urgent.length ? '/assets?risk=act_now' : '/scans'} className="btn btn-primary">{urgent.length ? 'Review priority assets' : 'View discovery scans'}<ArrowRight size={17}/></Link><div className="workflow-links"><Link to="/policies">Review policies<ArrowUpRight size={16}/></Link><Link to="/advisories">Plan a transition<ArrowUpRight size={16}/></Link></div></section>
    <section className="panel"><div className="section-heading"><div><h2>Migration timing distribution</h2><p>Current Mosca verdicts</p></div><Link to="/assets" className="text-link" aria-label="View inventory"><ArrowUpRight size={20}/></Link></div><div className="distribution-summary"><strong>{updated ? assets.length : '\u2014'}</strong><span>assets in inventory</span></div><div className="distribution-bar" aria-hidden="true">{groups.map(g => <span key={g.name} style={{width: `${assets.length ? g.count / assets.length * 100 : 0}%`, background: g.color}}/>)}</div><div className="risk-legend">{groups.map(g => <Link key={g.name} to={`/assets${g.filter ? `?risk=${g.filter}` : ''}`}><span><i style={{background:g.color}}/>{g.name}</span><strong>{updated ? g.count : '\u2014'}</strong></Link>)}</div></section></div>
    <section className="panel priority-table"><div className="section-heading"><div><h2>Assets requiring attention</h2><p>Highest planning scores first / Up to five priority assets</p></div><Link to="/assets?risk=act_now" className="text-link">View inventory<ArrowRight size={16}/></Link></div>{loading ? <div className="skeleton table-skeleton"/> : urgent.length ? <div className="data-table-container"><table className="data-table"><thead><tr><th>Cryptographic asset</th><th>Repository</th><th>Confidence</th><th>Planning score</th><th>Assessment</th><th><span className="sr-only">Details</span></th></tr></thead><tbody>{urgent.slice(0,5).map(a => <tr key={a.id}><td><Link className="asset-link" to={`/assets/${a.id}`}><span className="asset-icon"><Cube size={19}/></span><span>{a.algorithm}<small>{a.key_size ? `${a.key_size}-bit key` : a.curve || a.asset_type}</small></span></Link></td><td>{a.repository || 'Not reported'}</td><td><Badge variant="neutral">{a.confidence}</Badge></td><td className="font-mono">{a.qars_score ?? '\u2014'}</td><td><Badge variant="act-now">Act now</Badge></td><td><Link className="btn btn-ghost" aria-label={`Inspect ${a.algorithm}`} to={`/assets/${a.id}`}><ArrowUpRight size={18}/></Link></td></tr>)}</tbody></table></div> : <div className="empty-state"><ShieldCheck size={30}/><h3>{!updated ? 'Assessment unavailable' : assets.length ? 'No priority assets to review' : 'No discovery results yet'}</h3><p>{!updated ? 'Reconnect to load your cryptographic posture.' : assets.length ? 'Explore the inventory for monitoring and unassessed assets.' : 'Create a new scan to build your cryptographic inventory.'}</p><Link to="/scans" className="text-link">Open discovery scans<ArrowRight size={15}/></Link></div>}</section>
    <section className="panel"><div className="section-heading"><div><h2>Recent discovery</h2><p>Latest saved discovery runs</p></div><Link className="text-link" to="/scans">All scans<ArrowRight size={16}/></Link></div>{recent.length ? <div className="scan-list">{recent.map(s => <Link to={`/scans/${s.id}`} className="scan-row" key={s.id}><span className="asset-icon"><ScanIcon size={20}/></span><div><strong>{s.repository_name || s.repository_id}</strong><small>{s.commit_ref || 'File input'} / {new Date(s.created_at).toLocaleString()}</small></div><Badge variant={s.is_complete ? 'safe' : s.status === 'FAILED' ? 'act-now' : 'neutral'}>{s.is_complete ? 'Completed' : s.status}</Badge><ArrowUpRight size={17}/></Link>)}</div> : <p className="empty-inline">{loading ? 'Loading discovery runs...' : updated ? 'No scans yet. Use New scan to connect your first repository.' : 'Discovery history is unavailable.'}</p>}</section>
    <footer className="overview-footer"><span>ECDAT / Post-quantum transition workspace</span><span>{updated ? `Updated ${updated.toLocaleTimeString([], {hour:'2-digit',minute:'2-digit'})} / Refreshes every 30s` : 'Waiting for discovery data'}</span></footer>
  </div>;
}
