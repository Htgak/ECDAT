import { readJson } from '../api/response';
import { useCallback, useEffect, useRef, useState } from 'react';
import { Link, useNavigate, useParams } from 'react-router-dom';
import { AndroidLogo, ArrowLeft, ArrowRight, Check, Code, DownloadSimple, File, FileArrowUp, FolderSimple, GitBranch, SpinnerGap, WindowsLogo, X } from '@phosphor-icons/react';

type Kind = 'apk' | 'exe' | 'source' | 'git' | 'library' | 'container';
type Finding = { id?: string; algorithm: string; location: string; line: number | null; evidence: string; priority: string; recommendation: string; alternatives?: string[]; asset_type?: string; version?: string; mode?: string; key_size?: number; risk_score?: number; quantum_status?: string; sensitive_data_risk?: string; tradeoffs?: string; context?: Context; mosca?: { verdict: string; x_years: number | null; y_years: number | null; z_years: number | null; margin_years: number | null } };
type FileScan = {
  id: string; filename: string; kind: Kind; size: number;
  status: 'queued' | 'scanning' | 'completed' | 'failed';
  created_at: string; finding_count: number; review_count: number;
  findings?: Finding[]; limitations: string[]; error: string | null;
  assessment_version?: number; assessment?: { quantum_vulnerable: number; act_now: number }; context?: Context;
  inspected_files?: number; skipped_files?: number;
  repository_url?: string; commit?: string; snapshot_ready?: boolean; stage?: string;
};
type Context = {data_lifetime_years: number | ''; migration_years: number | ''; quantum_horizon_years: number | ''; criticality: string; sensitivity: string; exposure: string; priority: string};
const options = [
  {kind: 'container' as const, title: 'Container image', extension: 'Docker / OCI TAR', icon: FolderSimple, hint: 'Upload a saved image or rootfs TAR', accept: '.tar,.gz,.tgz'},
  {kind: 'library' as const, title: 'Binary library', extension: '.so, .dll, .jar, .a', icon: File, hint: 'Upload a binary library', accept: '.so,.dll,.dylib,.a,.jar,.zip'},
  { kind: 'git' as const, title: 'Git repository', extension: 'Public HTTPS URL', icon: GitBranch, hint: 'Scan a repository', accept: '' },
  { kind: 'apk' as const, title: 'Android app', extension: '.apk', icon: AndroidLogo, hint: 'Upload an APK file', accept: '.apk' },
  { kind: 'exe' as const, title: 'Windows app', extension: '.exe', icon: WindowsLogo, hint: 'Upload an EXE file', accept: '.exe' },
  { kind: 'source' as const, title: 'Source code', extension: '.zip or code file', icon: Code, hint: 'Upload a source ZIP or code file', accept: '.zip,.py,.java,.js,.ts,.jsx,.tsx,.c,.cpp,.h,.cs,.go,.rs,.kt,.swift,.php,.rb' },
];

function sizeLabel(bytes: number) { if (bytes === 0) return 'Size pending'; return bytes < 1048576 ? `${Math.max(1, Math.round(bytes / 1024))} KB` : `${(bytes / 1048576).toFixed(1)} MB`; }
function statusLabel(status: FileScan['status']) { return { queued: 'Queued', scanning: 'Scanning', completed: 'Completed', failed: 'Failed' }[status]; }
async function request<T>(url: string, init?: RequestInit): Promise<T> {
  const headers = init?.headers;
  const response = await fetch(url, { ...init, headers });
  if (!response.ok) {
    let message = 'Could not connect. Please try again.';
    try { const body = await response.json(); if (typeof body.detail === 'string') message = body.detail; } catch { /* Non-JSON proxy error. */ }
    if (response.status === 401) window.dispatchEvent(new Event('workspace-auth-expired'));
    throw Object.assign(new Error(message), {status: response.status});
  }
  return readJson(response);
}

export function UploadPage() {
  const { scanId } = useParams();
  const navigate = useNavigate();
  const [maxUploadBytes, setMaxUploadBytes] = useState(500 * 1024 * 1024);
  const [kind, setKind] = useState<Kind>('source');
  const [context, setContext] = useState<Context>({data_lifetime_years: '', migration_years: '', quantum_horizon_years: '', criticality: '', sensitivity: '', exposure: '', priority: ''});
  const [query, setQuery] = useState('');
  const [riskFilter, setRiskFilter] = useState('all');
  const [repositoryUrl, setRepositoryUrl] = useState('');
  const [repositoryRef, setRepositoryRef] = useState('');
  const [file, setFile] = useState<globalThis.File | null>(null);
  const [dragging, setDragging] = useState(false);
  const [uploading, setUploading] = useState(false);
  const [progress, setProgress] = useState(0);
  const [error, setError] = useState('');
  const [listError, setListError] = useState('');
  const [resultError, setResultError] = useState('');
  const [scans, setScans] = useState<FileScan[]>([]);
  const [listLoading, setListLoading] = useState(true);
  const [result, setResult] = useState<FileScan | null>(null);
  const [reviewOnly, setReviewOnly] = useState(false);
  const [visibleCount, setVisibleCount] = useState(100);
  const input = useRef<HTMLInputElement>(null);
  const transfer = useRef<XMLHttpRequest | null>(null);
  const suppliedContext = Object.fromEntries(Object.entries(context).filter(([, value]) => value !== ''));
  const selected = options.find(option => option.kind === kind)!;
  useEffect(() => {
    const controller = new AbortController();
    request<{max_upload_bytes: number}>('/api/v1/uploads/config', {signal: controller.signal}).then(config => setMaxUploadBytes(config.max_upload_bytes)).catch(() => {});
    return () => controller.abort();
  }, []);
  const maxUploadLabel = `${Math.round(maxUploadBytes / 1024 / 1024)} MB`;
  const loadScans = useCallback((signal?: AbortSignal) =>
    request<FileScan[]>('/api/v1/uploads', { signal }).then(records => {
      if (!signal?.aborted) { setScans(records); setListError(''); }
    }).catch(err => {
      if (!signal?.aborted) setListError(err instanceof Error ? err.message : 'Could not load saved scans.');
    }).finally(() => { if (!signal?.aborted) setListLoading(false); }), []);
  useEffect(() => {
    const controller = new AbortController();
    void loadScans(controller.signal);
    const timer = setInterval(() => void loadScans(controller.signal), 4000);
    return () => { controller.abort(); clearInterval(timer); };
  }, [loadScans]);
  useEffect(() => {
    if (!scanId) return;
    window.scrollTo(0, 0);
    const controller = new AbortController();
    let timer: ReturnType<typeof setTimeout>;
    const load = async () => {
      try {
        const record = await request<FileScan>(`/api/v1/uploads/${scanId}`, { signal: controller.signal });
        if (controller.signal.aborted) return;
        setResult(record); setResultError('');
        if (record.status === 'queued' || record.status === 'scanning') timer = setTimeout(load, 1500);
      } catch (err) {
        if (!controller.signal.aborted) { setResultError(err instanceof Error ? err.message : 'Could not load results.'); if (![401,404,422].includes((err as {status?:number}).status ?? 0)) timer = setTimeout(load, 5000); }
      }
    };
    void load();
    return () => { controller.abort(); clearTimeout(timer); };
  }, [scanId]);
  useEffect(() => () => transfer.current?.abort(), []);

  function chooseFile(chosen?: globalThis.File) {
    setError('');
    if (!chosen) return;
    const extension = '.' + chosen.name.split('.').pop()?.toLowerCase();
    if (!selected.accept.split(',').includes(extension)) { setError(`Choose ${selected.hint.toLowerCase().replace('upload ', '')}.`); setFile(null); return; }
    if (!chosen.size || chosen.size > maxUploadBytes) { setError(`Choose a non-empty file up to ${maxUploadLabel}.`); setFile(null); return; }
    setFile(chosen);
  }
  async function scanRepository() {
    if (uploading) return;
    setUploading(true); setError('');
    try {
      const record = await request<FileScan>('/api/v1/uploads/repository', {method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({url: repositoryUrl.trim(), ref: repositoryRef.trim(), context: suppliedContext})});
      setResult(record); setReviewOnly(false); void loadScans(); navigate(`/scans/${record.id}`);
    } catch (err) { setError(err instanceof Error ? err.message : 'Could not start the repository scan.'); }
    finally { setUploading(false); }
  }
  function upload() {
    if (!file || uploading) return;
    setUploading(true); setError(''); setProgress(0);
    const body = new FormData(); body.append('kind', kind); body.append('file', file); body.append('context', JSON.stringify(suppliedContext));
    const xhr = new XMLHttpRequest(); transfer.current = xhr;
    xhr.open('POST', '/api/v1/uploads'); xhr.timeout = 900000;
    xhr.upload.onprogress = event => { if (event.lengthComputable) setProgress(Math.round(event.loaded / event.total * 100)); };
    xhr.onload = () => {
      setUploading(false);
      try {
        const data = JSON.parse(xhr.responseText);
        if (xhr.status < 200 || xhr.status >= 300) throw new Error(typeof data.detail === 'string' ? data.detail : 'Upload failed. Please try again.');
        setResult(data); setFile(null); setReviewOnly(false); void loadScans(); navigate(`/scans/${data.id}`);
      } catch (err) { setError(err instanceof Error ? err.message : 'Upload failed. Please try again.'); }
    };
    xhr.onerror = () => { setUploading(false); setError('Connection lost. Please try uploading again.'); };
    xhr.ontimeout = () => { setUploading(false); setError('Upload timed out. Check Saved scans before trying again.'); };
    xhr.send(body);
  }
  const current = result?.id === scanId ? result : null;
  const findings = (current?.findings || []).filter(f => (!reviewOnly || f.priority === 'review') && (riskFilter === 'all' || f.mosca?.verdict === riskFilter) && `${f.algorithm} ${f.location} ${f.asset_type}`.toLowerCase().includes(query.toLowerCase()));
  const artifact = (name: string) => `/api/v1/uploads/${scanId}/artifacts/${name}`;

  return <div className="scan-workspace">
    <div className="scan-page-navigation"><div><span className="eyebrow">DISCOVERY</span><h1 className="page-title">Discovery scans</h1><p className="page-subtitle">Upload a file, review the findings, and keep the evidence together.</p></div><a className="btn btn-secondary" href="#saved-scans"><FolderSimple size={17} />Saved scans</a></div>
    <div className="simple-main" id="scan-content">
      {!scanId ? <>
        <div className="simple-intro"><h2>Start a scan</h2><p>Scan source repositories, applications, binary libraries, or saved container images.</p></div>
        <section className="upload-panel" aria-label="Upload and scan">
          <fieldset className="file-types" disabled={uploading}><legend>What would you like to scan?</legend><div className="file-type-options">{options.map(({ kind: value, title, extension, icon: Icon }) => <label key={value} className={`file-type ${kind === value ? 'selected' : ''}`}><input type="radio" name="file-kind" checked={kind === value} onChange={() => { setKind(value); setFile(null); setError(''); if (input.current) input.current.value = ''; }} /><Icon size={25} /><span><strong>{title}</strong><small>{extension}</small></span>{kind === value && <Check className="type-check" size={16} weight="bold" />}</label>)}</div></fieldset>
          {kind === 'git' ? <div className="repository-fields"><label>Repository URL<input type="url" value={repositoryUrl} onChange={event => setRepositoryUrl(event.target.value)} placeholder="https://github.com/owner/repository" disabled={uploading} /></label><label>Branch or tag (optional)<input value={repositoryRef} onChange={event => setRepositoryRef(event.target.value)} placeholder="Default branch" disabled={uploading} /></label><p>Public GitHub, GitLab, and Bitbucket repositories. Your source snapshot is saved with the scan.</p></div> : <>
          <input ref={input} className="visually-hidden" type="file" accept={selected.accept} onChange={event => chooseFile(event.target.files?.[0])} disabled={uploading} tabIndex={-1} aria-label="Choose file" />
          {!file ? <button type="button" className={`drop-zone ${dragging ? 'dragging' : ''}`} disabled={uploading} onClick={() => input.current?.click()} onDragOver={event => { event.preventDefault(); setDragging(true); }} onDragLeave={() => setDragging(false)} onDrop={event => { event.preventDefault(); setDragging(false); if (event.dataTransfer.files.length > 1) setError('Upload one file at a time. ZIP a source folder first.'); else chooseFile(event.dataTransfer.files[0]); }}><span className="upload-symbol"><FileArrowUp size={31} /></span><strong>{selected.hint}</strong><span>Drop your file here, or <u>browse files</u></span><small>Up to {maxUploadLabel}</small></button> : <div className="selected-file"><span className="file-symbol"><File size={26} /></span><div><strong>{file.name}</strong><span>{sizeLabel(file.size)} · Ready to scan</span></div><button className="simple-icon-button" aria-label="Remove file" disabled={uploading} onClick={() => { setFile(null); if (input.current) input.current.value = ''; }}><X size={19} /></button></div>}
          </>}
          <fieldset className="assessment-context" disabled={uploading}><legend>Risk assessment assumptions</legend><p>Mosca compares data lifetime (X) + migration time (Y) against your quantum arrival scenario (Z). Enter your application context. Leave unknown values blank; missing context is shown as not assessed.</p><div className="context-grid">
            {([['data_lifetime_years', 'Data lifetime X (years)', 100, 0], ['migration_years', 'Migration time Y (years)', 30, 0], ['quantum_horizon_years', 'Quantum horizon Z (years)', 100, 0.1]] as const).map(([key, label, max, min]) => <label key={key}>{label}<input type="number" min={min} max={max} step="0.1" value={context[key]} onChange={e => setContext({...context, [key]: e.target.value === '' ? '' : Number(e.target.value)})}/></label>)}
            {([['criticality', 'Business criticality', ['low', 'medium', 'high', 'critical']], ['sensitivity', 'Data sensitivity', ['public', 'internal', 'confidential', 'restricted']], ['exposure', 'Exposure', ['internal', 'external']], ['priority', 'Migration priority', ['balanced', 'latency', 'cost', 'assurance']]] as const).map(([key, label, values]) => <label key={key}>{label}<select value={context[key]} onChange={e => setContext({...context, [key]: e.target.value})}><option value="">Not provided</option>{values.map(value => <option key={value}>{value}</option>)}</select></label>)}
          </div></fieldset>
          {error && <p className="simple-error" role="alert">{error}</p>}
          {uploading && kind !== 'git' && <div className="upload-progress" role="status"><progress max={100} value={progress} /><span>{progress === 100 ? 'Preparing your scan...' : `Uploading ${progress}%`}</span></div>}
          <div className="upload-bottom"><p>Your file and reports are saved with the scan.</p><button className="simple-button primary" disabled={uploading || (kind === 'git' ? !repositoryUrl.trim() : !file)} onClick={kind === 'git' ? scanRepository : upload}>{uploading ? <><SpinnerGap className="simple-spin" size={18} />Uploading</> : <>{kind === 'git' ? 'Scan repository' : 'Scan file'}<ArrowRight size={18} /></>}</button></div>
        </section>
        <p className="scope-note">{kind === 'source' || kind === 'git' ? 'Python and Java source analysis. Other code files are checked for cryptographic indicators.' : 'Static inspection for cryptographic indicators. Your app is not executed.'}</p>
      </> : <section className="result-section" aria-label="Scan results">
        <Link to="/scans" className="back-link"><ArrowLeft size={16} />Start another scan</Link>
        {resultError && <p className="simple-error" role="alert">{resultError}</p>}
        {!current ? resultError ? <Link to="/scans" className="simple-button">Return to discovery scans</Link> : <div className="result-loading" role="status"><SpinnerGap className="simple-spin" size={25} />Loading your scan...</div> : <>
          <div className="result-heading"><div><p className="simple-eyebrow">{current.kind === 'source' ? 'SOURCE CODE' : current.kind.toUpperCase()}</p><h1>{current.filename}</h1>{current.repository_url && <p className="repository-origin">{current.repository_url}{current.commit && <><br />Revision {current.commit.slice(0, 12)}</>}</p>}<p>{sizeLabel(current.size)} · {new Date(current.created_at).toLocaleString()}</p></div><span className={`scan-status ${current.status}`}>{statusLabel(current.status)}</span></div>
          {current.status === 'queued' || current.status === 'scanning' ? <div className="scan-in-progress" role="status"><SpinnerGap className="simple-spin" size={30} /><h2>{current.status === 'queued' ? 'Your scan is queued.' : current.stage || 'Scanning your file...'}</h2><p>You can leave this page. Your results will be in Saved scans.</p></div> : current.status === 'failed' ? <div className="simple-error" role="alert"><strong>The scan could not finish.</strong><p>{current.error}</p><Link to="/scans">Start another scan</Link></div> : <>
            <div className="result-summary"><span className={`summary-icon ${current.review_count ? 'review' : ''}`}><Check size={24} /></span><div><h2>{current.finding_count ? `${current.finding_count} cryptographic ${current.finding_count === 1 ? 'finding' : 'findings'}` : 'No cryptographic indicators found'}</h2><p>{current.review_count ? `${current.review_count} ${current.review_count === 1 ? 'finding needs' : 'findings need'} review.` : 'No review items detected. This does not establish that the file is secure.'} {current.inspected_files} {current.inspected_files === 1 ? 'file inspected.' : 'files inspected.'}</p></div></div>
            {current.assessment && <section className="assessment-context"><h2>Quantum risk assessment</h2><p>{current.assessment.quantum_vulnerable} potentially quantum-vulnerable assets · {current.assessment.act_now} exceed the migration horizon.</p><p>Scenario: X = {current.context?.data_lifetime_years ?? 'Not provided'}, Y = {current.context?.migration_years ?? 'Not provided'}, Z = {current.context?.quantum_horizon_years ?? 'Not provided'} years. Scores are planning priorities, not attack probabilities.</p></section>}
            <div className="context-grid"><label>Search findings<input value={query} onChange={e => setQuery(e.target.value)} placeholder="Algorithm, type, or location"/></label><label>Mosca category<select value={riskFilter} onChange={e => setRiskFilter(e.target.value)}><option value="all">All categories</option><option value="act_now">Act now</option><option value="monitor">Monitor</option><option value="not_assessed">Not assessed</option><option value="within_horizon">Within selected horizon</option><option value="not_applicable">Not applicable / requires review</option></select></label></div>
            {current.finding_count > 0 && <div className="findings-section"><div className="findings-heading"><h2>Findings</h2><label><input type="checkbox" checked={reviewOnly} onChange={event => setReviewOnly(event.target.checked)} />Needs review only</label></div><div className="simple-findings">{findings.slice(0, visibleCount).map((finding, index) => <details key={`${finding.location}-${finding.algorithm}-${index}`} className="finding" id={finding.id}><summary><span className={`finding-marker ${finding.priority}`} /><strong>{finding.algorithm}</strong><span className="finding-location">{finding.location}{finding.line ? `:${finding.line}` : ''}</span><span className={`finding-badge ${finding.priority}`}>{finding.priority === 'review' ? 'Review' : 'Detected'}</span></summary><div className="finding-details">{!!finding.alternatives?.length && <p><strong>Suggested replacements: {finding.alternatives.join(' / ')}</strong></p>}<p>{finding.recommendation}</p>{finding.mosca && <><p><strong>{finding.asset_type} · {finding.context?.criticality} criticality · {finding.context?.sensitivity}</strong></p><p>Version: {finding.version || 'Unknown'} · Mode: {finding.mode || 'Unknown'} · Key size: {finding.key_size || 'Unknown'}</p><p>Risk score: {finding.risk_score == null ? 'Not assessed' : `${finding.risk_score}/100`} · {finding.quantum_status?.replaceAll('_', ' ')}</p><p>Mosca: {finding.mosca.verdict.replaceAll('_', ' ')}{finding.mosca.x_years != null && finding.mosca.y_years != null ? `; X + Y = ${finding.mosca.x_years + finding.mosca.y_years} years; Z = ${finding.mosca.z_years} years; margin = ${finding.mosca.margin_years} years.` : '; provide planning context to calculate.'}</p><p>{finding.sensitive_data_risk}</p><p>{finding.tradeoffs}</p></>}<small>{finding.evidence}{finding.evidence === 'String indicator' ? ' — confirm whether this algorithm is actually used.' : ''}</small></div></details>)}{!findings.length && <p className="simple-empty">No findings match this filter.</p>}{findings.length > visibleCount && <button className="simple-button" onClick={() => setVisibleCount(count => count + 100)}>Show next {Math.min(100, findings.length - visibleCount)} findings</button>}</div></div>}
            <details className="scan-scope"><summary>What this scan covers</summary>{current.limitations.map((text, index) => <p key={index}>{text}</p>)}{!!current.skipped_files && <p>{current.skipped_files} unsupported files were skipped.</p>}</details>
          </>}
          <div className="saved-artifacts"><div><h2>Saved artifacts</h2><p>Download your file or scan results.</p></div><div className="artifact-links">{(current.kind !== 'git' || current.snapshot_ready) && <a className="simple-button" href={artifact('original')}><DownloadSimple size={17} />{current.kind === 'git' ? 'Source snapshot' : 'Original file'}</a>}{current.status === 'completed' && <><a className="simple-button" href={artifact('report')}><DownloadSimple size={17} />Report (JSON)</a><a className="simple-button" href={artifact('findings')}><DownloadSimple size={17} />Findings (CSV)</a>{current.assessment_version && <><a className="simple-button" href={artifact('cbom')}>CycloneDX CBOM</a><a className="simple-button" href={artifact('sarif')}>SARIF</a><a className="simple-button" href={artifact('checksums')}>Checksums</a></>}</>}</div></div>
        </>}
      </section>}
      <section id="saved-scans" className="saved-scans"><div className="saved-heading"><h2>Saved scans</h2><span>{scans.length ? `${scans.length} ${scans.length === 1 ? 'file' : 'files'}` : ''}</span></div>{listError ? <div className="simple-error" role="alert">{listError}<button className="simple-button" onClick={() => void loadScans()}>Retry</button></div> : listLoading ? <p className="simple-empty" role="status">Loading saved scans...</p> : !scans.length ? <div className="empty-scans"><FolderSimple size={24} /><p>Your scans will appear here.<span>Files and results stay together, ready to reopen.</span></p></div> : <div className="saved-list">{scans.map(scan => <Link key={scan.id} to={`/scans/${scan.id}`} className={`saved-row ${scan.id === scanId ? 'current' : ''}`} onClick={() => setReviewOnly(false)}><span className="file-symbol"><File size={22} /></span><div className="saved-filename"><strong>{scan.filename}</strong><span>{scan.kind === 'source' ? 'Source code' : scan.kind.toUpperCase()} · {sizeLabel(scan.size)} · {new Date(scan.created_at).toLocaleDateString()}</span></div><span className={`scan-status ${scan.status}`}>{statusLabel(scan.status)}</span><ArrowRight size={17} /></Link>)}</div>}</section>
    </div>
  </div>;
}
