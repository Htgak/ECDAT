import React, { useEffect, useState, useMemo, useCallback } from 'react';
import { Link, useSearchParams } from 'react-router-dom';
import {
  MagnifyingGlass,
  ArrowRight,
  ArrowClockwise,
  DownloadSimple,
  FunnelSimple,
} from '@phosphor-icons/react';
import { Card } from '../components/ui/Card';
import { Badge } from '../components/ui/Badge';
import { apiClient } from '../api/client';
import type { Asset } from '../api/types';

/* Verdict badge helper */
function VerdictBadge({ verdict }: { verdict: string | null | undefined }) {
  if (verdict === 'act_now') return <Badge variant="act-now">Act Now</Badge>;
  if (verdict === 'safe')    return <Badge variant="safe">Within horizon</Badge>;
  if (verdict === 'monitor') return <Badge variant="monitor">Monitor</Badge>;
  return <Badge variant="neutral">Not assessed</Badge>;
}

export const AssetExplorerPage: React.FC = () => {
  const [params, setParams] = useSearchParams();
  const [error, setError] = useState('');
  const [assets,     setAssets]     = useState<Asset[]>([]);
  const [loading,    setLoading]    = useState(true);
  const searchTerm = params.get('q') || '';
  const riskFilter = params.get('risk') || 'ALL';
  const setSearchTerm = (value: string) => setParams(prev => { const next = new URLSearchParams(prev); next.set('q', value); return next; }, { replace: true });
  const setRiskFilter = (value: string) => setParams(prev => { const next = new URLSearchParams(prev); next.set('risk', value); return next; }, { replace: true });
  const [confFilter, setConfFilter] = useState('ALL');

  const loadAssets = useCallback(async () => {
    setLoading(true);
    try {
      const res = await apiClient.getAllAssets();
      setAssets(res);
      setError('');
    } catch { setError('Could not load inventory. Check the API connection and refresh.'); } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void Promise.resolve().then(loadAssets);
    const id = setInterval(loadAssets, 30_000);
    return () => clearInterval(id);
  }, [loadAssets]);

  const filtered = useMemo(() => {
    const q = searchTerm.toLowerCase();
    return assets.filter(a => {
      const matchSearch =
        a.algorithm.toLowerCase().includes(q) ||
        (a.repository && a.repository.toLowerCase().includes(q)) ||
        (a.provider  && a.provider.toLowerCase().includes(q))  ||
        a.stable_id.toLowerCase().includes(q);
      const matchRisk = riskFilter === 'ALL' || a.mosca_verdict === riskFilter;
      const matchConf = confFilter === 'ALL' || a.confidence === confFilter;
      return matchSearch && matchRisk && matchConf;
    });
  }, [assets, searchTerm, riskFilter, confFilter]);

  const counts = useMemo(() => ({
    actNow:  assets.filter(a => a.mosca_verdict === 'act_now').length,
    monitor: assets.filter(a => a.mosca_verdict === 'monitor').length,
    safe:    assets.filter(a => a.mosca_verdict === 'safe').length,
  }), [assets]);

  return (
    <div className="page-container">
      {error && <div className="error-banner" role="alert"><span>{error}</span><button className="btn btn-secondary" onClick={loadAssets}>Retry</button></div>}
      {/* â”€â”€ Header â”€â”€ */}
      <div className="page-header">
        <div>
          <h1 className="page-title">Cryptographic Inventory</h1>
          <p className="page-subtitle">
            All algorithms, keys, and certificates discovered across codebases.
          </p>
        </div>
        <div className="page-actions">
          <button className="btn btn-ghost btn-sm" onClick={loadAssets} title="Refresh inventory">
            <ArrowClockwise size={14} className={loading ? 'spin-anim' : ''} />
          </button>
          <Link to="/exports" className="btn btn-primary btn-sm">
            <DownloadSimple size={13} />
            Export CBOM
          </Link>
        </div>
      </div>

      {/* â”€â”€ Mini stat pills â”€â”€ */}
      {!loading && (
        <div style={{ display: 'flex', gap: '10px', flexWrap: 'wrap' }}>
          {[
            { label: `${counts.actNow} Act Now`,   variant: 'act-now' as const, filter: 'act_now' },
            { label: `${counts.monitor} Monitor`,  variant: 'monitor' as const, filter: 'monitor' },
            { label: `${counts.safe} Within horizon`,         variant: 'safe'    as const, filter: 'safe' },
          ].map(({ label, variant, filter }) => (
            <button
              key={filter}
              onClick={() => setRiskFilter(riskFilter === filter ? 'ALL' : filter)}
              style={{
                background: 'none', border: 'none', padding: 0, cursor: 'pointer',
                opacity: riskFilter !== 'ALL' && riskFilter !== filter ? 0.4 : 1,
                transition: 'opacity 0.15s ease',
              }}
            >
              <Badge variant={variant}>{label}</Badge>
            </button>
          ))}
          {riskFilter !== 'ALL' && (
            <button
              onClick={() => setRiskFilter('ALL')}
              style={{ background: 'none', border: 'none', padding: 0, cursor: 'pointer', fontSize: '11px', color: 'var(--text-dim)' }}
            >
              Clear filter Ã—
            </button>
          )}
        </div>
      )}

      {/* â”€â”€ Filter / Search Bar â”€â”€ */}
      <Card style={{ padding: '0', overflow: 'hidden' }}>
        <div className="filter-bar">
          {/* Search */}
          <div style={{ position: 'relative', flex: 1, minWidth: '220px' }}>
            <MagnifyingGlass
              size={14}
              style={{ position: 'absolute', left: '10px', top: '50%', transform: 'translateY(-50%)', color: 'var(--text-dim)' }}
            />
            <input
              type="text"
              className="input-control"
              placeholder="Search algorithm, repository, IDâ€¦"
              value={searchTerm}
              onChange={e => setSearchTerm(e.target.value)}
              style={{ paddingLeft: '32px' }}
            />
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
            <FunnelSimple size={13} color="var(--text-dim)" />
          </div>

          {/* Risk filter */}
          <div className="filter-group">
            <span className="filter-label">Risk</span>
            <select className="filter-select" value={riskFilter} onChange={e => setRiskFilter(e.target.value)}>
              <option value="ALL">All levels</option>
              <option value="act_now">Act Now</option>
              <option value="monitor">Monitor</option><option value="not_assessed">Not assessed</option><option value="not_applicable">Not applicable</option>
              <option value="safe">Within horizon</option>
            </select>
          </div>

          {/* Confidence filter */}
          <div className="filter-group">
            <span className="filter-label">Confidence</span>
            <select className="filter-select" value={confFilter} onChange={e => setConfFilter(e.target.value)}>
              <option value="ALL">All</option>
              <option value="OBSERVED">Observed</option><option value="INDICATOR">Indicator</option>
            </select>
          </div>
        </div>
      </Card>

      {/* â”€â”€ Inventory Table â”€â”€ */}
      <Card style={{ padding: '0', overflow: 'hidden' }}>
        <div style={{ padding: '12px 18px', borderBottom: '1px solid var(--border-subtle)', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <span style={{ fontSize: '12px', color: 'var(--text-dim)' }}>
            {loading ? 'Loadingâ€¦' : `${filtered.length} of ${assets.length} assets`}
          </span>
          <span className="font-mono" style={{ fontSize: '10px', color: 'var(--text-dim)' }}>
            SHA-256 Stable IDs
          </span>
        </div>

        {loading ? (
          <div style={{ padding: '16px 20px', display: 'flex', flexDirection: 'column', gap: '8px' }}>
            {[0, 1, 2, 3, 4].map(i => (
              <div key={i} className="skeleton" style={{ height: '42px', borderRadius: '6px' }} />
            ))}
          </div>
        ) : (
          <div className="data-table-container" style={{ border: 'none', borderRadius: 0 }}>
            <table className="data-table">
              <thead>
                <tr>
                  <th>Algorithm</th>
                  <th>Repository</th>
                  <th>Key / Curve</th>
                  <th>Confidence</th>
                  <th>Planning</th>
                  <th>Verdict</th>
                  <th>Occurrences</th>
                  <th style={{ width: '70px' }}>Detail</th>
                </tr>
              </thead>
              <tbody>
                {filtered.map(asset => {
                  const isActNow = asset.mosca_verdict === 'act_now';
                  const isSafe   = asset.mosca_verdict === 'safe';
                  return (
                    <tr key={asset.id}>
                      <td>
                        <div style={{ display: 'flex', flexDirection: 'column' }}>
                          <span style={{
                            fontWeight: 700,
                            color: isActNow ? 'var(--color-act-now)' : isSafe ? 'var(--color-safe)' : 'var(--text-main)',
                          }}>
                            {asset.algorithm}
                          </span>
                          <span className="font-mono" style={{ fontSize: '10px', color: 'var(--text-dim)', marginTop: '1px' }}>
                            {asset.stable_id.substring(0, 16)}â€¦
                          </span>
                        </div>
                      </td>
                      <td>
                        <span style={{ fontWeight: 500 }}>{asset.repository || 'Not reported'}</span>
                        <br />
                        <span style={{ fontSize: '10px', color: 'var(--text-dim)' }}>{asset.exposure || 'Exposure not assessed'}</span>
                      </td>
                      <td>
                        <span className="font-mono" style={{ fontSize: '12px' }}>
                          {asset.key_size ? `${asset.key_size} bit` : asset.curve || 'Not reported'}
                        </span>
                      </td>
                      <td>
                        <Badge variant={asset.confidence === 'CONFIRMED' ? 'cyan' : 'neutral'}>
                          {asset.confidence}
                        </Badge>
                      </td>
                      <td>
                        <span
                          className="font-mono"
                          style={{
                            fontWeight: 700,
                            color: isActNow ? 'var(--color-act-now)' : isSafe ? 'var(--color-safe)' : 'var(--color-monitor)',
                          }}
                        >
                          {asset.qars_score ?? 'â€”'}
                        </span>
                      </td>
                      <td>
                        <VerdictBadge verdict={asset.mosca_verdict} />
                      </td>
                      <td>
                        <span className="font-mono" style={{ fontWeight: 600 }}>{asset.occurrences_count ?? 'Not reported'}</span>
                      </td>
                      <td>
                        <Link to={`/assets/${asset.id}`} className="btn btn-ghost btn-xs" style={{ gap: '3px' }}>
                          Open <ArrowRight size={11} />
                        </Link>
                      </td>
                    </tr>
                  );
                })}

                {filtered.length === 0 && (
                  <tr>
                    <td colSpan={8} style={{ textAlign: 'center', padding: '36px', color: 'var(--text-dim)' }}>
                      No assets match your filters.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        )}
      </Card>

      <style>{`
        .spin-anim { animation: spin-icon 0.8s linear infinite; }
        @keyframes spin-icon { 0%{transform:rotate(0)} 100%{transform:rotate(360deg)} }
      `}</style>
    </div>
  );
};
