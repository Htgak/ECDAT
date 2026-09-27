import { useState } from 'react';
import { Link } from 'react-router-dom';
import { DownloadSimple, ArrowRight, FileCode, Table } from '@phosphor-icons/react';
const formats = [
  {id:'cyclonedx',title:'Cryptography bill of materials',label:'CycloneDX 1.6',description:'Cryptographic assets and their discovery locations in CBOM format.',file:'ecdat-inventory.cdx.json',icon:FileCode},
  {id:'sarif',title:'Source findings',label:'SARIF 2.1',description:'Discovery observations for compatible code analysis tools.',file:'ecdat-inventory.sarif',icon:FileCode},
  {id:'csv',title:'Inventory spreadsheet',label:'CSV',description:'Algorithms, source locations, and persisted risk scores.',file:'ecdat-inventory.csv',icon:Table},
];
export function ExportCenterPage() {
  const [busy,setBusy]=useState<string|null>(null);
  const [error,setError]=useState('');
  async function download(format: typeof formats[number]) {
    setBusy(format.id);setError('');
    try {
      const response=await fetch(`/api/v1/workspace/export/${format.id}`, { headers: {} });
      if(response.status===401) window.dispatchEvent(new Event('workspace-auth-expired'));
      if(response.headers.get('content-type')?.includes('text/html')) throw new Error('The API returned a web page instead of a report. Check the backend and frontend proxy.');
      if(!response.ok) throw new Error('Could not generate the report. Please try again.');
      const url=URL.createObjectURL(await response.blob());
      const anchor=document.createElement('a');anchor.href=url;anchor.download=format.file;
      document.body.appendChild(anchor);anchor.click();anchor.remove();setTimeout(()=>URL.revokeObjectURL(url),1000);
    } catch(error) {setError(error instanceof Error ? error.message : 'Download failed.');}
    finally {setBusy(null);}
  }
  return <div className="page-container">
    <div className="page-header"><div><h1 className="page-title">Export inventory</h1><p className="page-subtitle">Download saved scan findings in a format your team can use.</p></div></div>
    {error && <p role="alert" className="error-banner">{error}</p>}
    <div className="export-formats">{formats.map(format=><section className="panel" key={format.id}><format.icon size={25} className="text-cyan"/><p className="eyebrow">{format.label}</p><h2>{format.title}</h2><p className="text-muted">{format.description}</p><button className="btn btn-secondary" onClick={()=>void download(format)} disabled={busy!==null}><DownloadSimple size={17}/>{busy===format.id ? 'Preparing report...' : 'Download report'}</button></section>)}</div>
    <section className="panel"><h2>Looking for an uploaded file?</h2><p className="page-subtitle">Original uploads and their saved reports stay with each scan.</p><Link className="text-link export-scan-link" to="/scans">Open Discovery scans<ArrowRight size={16}/></Link></section>
  </div>;
}
