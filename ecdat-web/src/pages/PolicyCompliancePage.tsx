import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { apiClient } from '../api/client';
import { Badge } from '../components/ui/Badge';
import type { PolicyResult } from '../api/types';
export function PolicyCompliancePage() {
  const [rows,setRows] = useState<PolicyResult[]>([]);
  const [loading,setLoading] = useState(true);
  const [error,setError] = useState('');
  const [refresh,setRefresh] = useState(0);
  const [verdict,setVerdict] = useState('all');
  useEffect(() => {
    let active = true;
    apiClient.getPolicies().then(result => {if(active){setRows(result);setError('');}}).catch(() => {if(active)setError('Could not load policy results. Retry using Refresh results.');}).finally(() => {if(active)setLoading(false);});
    return () => {active=false;};
  }, [refresh]);
  const filtered=rows.filter(row=>verdict==='all'||row.verdict===verdict);
  return <div className="page-container"><div className="page-header"><div><h1 className="page-title">Policy review</h1><p className="page-subtitle">ECDAT baseline 1.0.0 evaluates saved findings. These checks support review; they do not certify FIPS, CNSA or PCI compliance.</p></div><button className="btn btn-secondary" onClick={()=>setRefresh(v=>v+1)}>Refresh results</button></div>
    {error && <p className="error-banner" role="alert">{error}</p>}
    <div className="policy-filters" role="group" aria-label="Policy verdict filter">{['all','fail','warn','unknown','pass'].map(value=><button className={`btn ${verdict===value?'btn-primary':'btn-secondary'}`} key={value} onClick={()=>setVerdict(value)} aria-pressed={verdict===value}>{value} ({value==='all'?rows.length:rows.filter(row=>row.verdict===value).length})</button>)}</div>
    {loading ? <p role="status">Loading policy results...</p> : !filtered.length ? <section className="panel"><h2>No applicable results</h2><p>{rows.length ? 'No findings match this filter.' : 'Run a scan to evaluate detected legacy algorithms, RSA key sizes, quantum-vulnerable public keys and private-key material.'}</p><Link to="/scans">Open discovery scans</Link></section> : <div className="policy-results">{filtered.map(row=><article className="panel policy-result" key={row.id}><div><Badge variant={row.verdict==='fail'?'act-now':row.verdict==='warn'?'monitor':row.verdict==='pass'?'safe':'neutral'}>{row.verdict}</Badge><h2>{row.rule_name}</h2><p className="text-muted">{row.rule_id} / {row.severity} / {row.asset_algorithm}</p><p>{row.explanation}</p><p>{row.offending_property}: {row.offending_value ?? 'Not observed'}</p><p className="evidence-path">{row.location}</p><Link to={`/scans/${row.scan_id}`}>Open scan evidence</Link></div></article>)}</div>}
  </div>;
}
