import { useEffect, useMemo, useState } from 'react';
import { Link } from 'react-router-dom';
import { ArrowRight, ArrowClockwise } from '@phosphor-icons/react';
import { apiClient } from '../api/client';
import type { PQCAdvisory } from '../api/types';

export function AdvisoriesPage() {
  const [items, setItems] = useState<PQCAdvisory[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [search, setSearch] = useState('');
  const [refresh, setRefresh] = useState(0);
  useEffect(() => {
    let active = true;
    apiClient.getAdvisories().then(data => { if (active) {setItems(data); setError('');} }).catch(() => { if (active) setError('Could not load scan recommendations. Retry to reconnect.'); }).finally(() => { if (active) setLoading(false); });
    return () => {active = false;};
  }, [refresh]);
  const groups = useMemo(() => {
    const result = new Map<string, {item: PQCAdvisory; sources: PQCAdvisory[]}>();
    for (const item of items) {
      if (!`${item.classical_algorithm} ${item.pqc_replacement} ${item.filename} ${item.location}`.toLowerCase().includes(search.toLowerCase())) continue;
      const key = JSON.stringify([item.classical_algorithm, item.recommendation, item.evidence, item.tradeoffs]);
      const group = result.get(key);
      if (group) group.sources.push(item); else result.set(key, {item, sources:[item]});
    }
    return [...result.entries()];
  }, [items, search]);
  return <div className="page-container recommendations-page">
    <div className="page-header"><div><p className="eyebrow">MIGRATION PLANNING</p><h1 className="page-title">Algorithm suggestions</h1><p className="page-subtitle">Replacement options backed by your saved findings. Confirm the operation and implementation support before migrating.</p></div><button className="btn btn-secondary" onClick={() => setRefresh(value => value + 1)} aria-label="Refresh suggestions"><ArrowClockwise size={18}/></button></div>
    <div className="recommendations-toolbar"><label htmlFor="recommendation-search">Search findings<input id="recommendation-search" className="input-control" value={search} onChange={event => setSearch(event.target.value)} placeholder="Algorithm, replacement, file or location"/></label><span>{groups.length} suggestion groups / {items.length} observations</span></div>
    {error ? <p role="alert" className="error-banner">{error}</p> : loading ? <p role="status">Loading scan findings...</p> : !groups.length ? <section className="panel"><h2>No matching suggestions</h2><p>{items.length ? 'Try a different search.' : 'Run a discovery scan to see replacement suggestions.'}</p><Link to="/scans">Open discovery scans</Link></section> : <div className="recommendations-list">{groups.map(([key, {item, sources}]) => <article className="recommendation-row" key={key}>
      <div className="recommendation-algorithm"><span className="eyebrow">DETECTED</span><h2>{item.classical_algorithm}</h2><span className="badge badge-neutral">{sources.length} {sources.length === 1 ? 'observation' : 'observations'}</span><p>{item.evidence}</p></div>
      <div className="recommendation-main"><span className="eyebrow">{item.alternatives?.length ? 'EVALUATE REPLACEMENT' : 'REVIEW CONFIGURATION'}</span><h3>{item.pqc_replacement}</h3><p>{item.recommendation}</p><details><summary>Implementation tradeoffs</summary><p>{item.tradeoffs}</p></details>{!!item.references?.length && <nav className="recommendation-references" aria-label={`${item.classical_algorithm} standards`}>{item.references.map(url => <a key={url} href={url} target="_blank" rel="noreferrer">NIST FIPS {url.match(/fips\/(\d+)/)?.[1] || 'reference'}</a>)}</nav>}</div>
      <div className="recommendation-evidence"><h4>Evidence locations</h4>{sources.slice(0, 3).map(source => <Link key={source.id} to={`/scans/${source.scan_id}`}><span>{source.filename}<small>{source.location}</small></span><ArrowRight size={16}/></Link>)}{sources.length > 3 && <details><summary>{sources.length - 3} more observations</summary>{sources.slice(3).map(source => <Link key={source.id} to={`/scans/${source.scan_id}`}><span>{source.filename}<small>{source.location}</small></span></Link>)}</details>}</div>
    </article>)}</div>}
  </div>;
}
