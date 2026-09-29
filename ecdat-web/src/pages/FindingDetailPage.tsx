import { readJson } from '../api/response';
import { API_BASE } from '../api/client';
import { useEffect, useState } from 'react';
import { Link, useParams } from 'react-router-dom';

type Detail = {id: string; scan_id: string; filename: string; algorithm: string; asset_type: string; confidence: string; qars_score: number | null; finding: {location: string; line?: number; evidence: string; version?: string; mode?: string; key_size?: number; recommendation: string; tradeoffs: string; alternatives: string[]; sensitive_data_risk: string; context: Record<string, string | number>; mosca: {verdict: string; x_years: number | null; y_years: number | null; z_years: number | null; margin_years: number | null}}};
export function FindingDetailPage() {
  const {id} = useParams();
  const [data, setData] = useState<Detail | null>(null);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(true);
  useEffect(() => {
    const controller = new AbortController();
    async function load() {
      try {
        const response = await fetch(`${API_BASE}/workspace/assets/${id}`, {signal:controller.signal, headers: {}});
        const result = await readJson(response);
        if (!controller.signal.aborted) {setData(result); setError('');}
      } catch (err) { if (!controller.signal.aborted) setError(err instanceof Error ? err.message : 'Could not load finding.'); }
      finally { if (!controller.signal.aborted) setLoading(false); }
    }
    void load(); return () => controller.abort();
  }, [id]);
  return <div className="page-container"><Link className="text-link" to="/assets">Back to inventory</Link>{loading ? <p role="status">Loading finding...</p> : error ? <p role="alert" className="error-banner">{error}<button className="btn btn-secondary" onClick={() => window.location.reload()}>Retry</button></p> : data && <>
    <div className="page-header"><div><p className="eyebrow">{data.asset_type}</p><h1 className="page-title">{data.algorithm}</h1><p className="page-subtitle">{data.filename}</p></div><Link className="btn btn-secondary" to={`/scans/${data.scan_id}`}>Open source scan</Link></div>
    <div className="finding-detail-grid"><section className="panel"><h2>Observed evidence</h2><dl className="evidence-definition">{Object.entries({Location: data.finding.location, Line: data.finding.line, Evidence: data.finding.evidence, Confidence: data.confidence, Version: data.finding.version, Mode: data.finding.mode, 'Key bits': data.finding.key_size}).map(([key, value]) => <div key={key}><dt>{key}</dt><dd>{value ?? 'Not reported'}</dd></div>)}</dl></section>
    <section className="panel"><h2>Migration suggestion</h2>{data.finding.alternatives.length > 0 && <h3>{data.finding.alternatives.join(' / ')}</h3>}<p>{data.finding.recommendation}</p><p className="text-muted">{data.finding.tradeoffs}</p></section>
    <section className="panel"><h2>Risk assessment</h2><p>Planning score: {data.qars_score == null ? 'Not assessed' : `${data.qars_score}/100`}</p><p>Mosca: {data.finding.mosca.verdict.replaceAll('_',' ')}</p>{data.finding.mosca.x_years != null && <p>X = {data.finding.mosca.x_years}, Y = {data.finding.mosca.y_years}, Z = {data.finding.mosca.z_years} years. Margin: {data.finding.mosca.margin_years} years.</p>}<p>{data.finding.sensitive_data_risk}</p></section>
    <section className="panel"><h2>Supplied business context</h2>{Object.keys(data.finding.context).length ? <dl className="evidence-definition">{Object.entries(data.finding.context).map(([key,value]) => <div key={key}><dt>{key.replaceAll('_',' ')}</dt><dd>{value}</dd></div>)}</dl> : <p>No business context supplied. Run a new scan with planning inputs to calculate risk.</p>}</section></div>
  </>}</div>;
}
