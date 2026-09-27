import { readJson } from '../api/response';
import { useEffect, useState, type FormEvent } from 'react';
import { useWorkspaceUser } from '../components/WorkspaceUserContext';

type Account = {id:string; username:string; role:string; active:boolean; source:string};
async function request(path:string, init?:RequestInit) {
  const response=await fetch('/api/v1/admin/users'+path,init);
  if(response.status===401)window.dispatchEvent(new Event('workspace-auth-expired'));
  const data=await readJson(response);
  if(!response.ok)throw new Error(typeof data.detail==='string'?data.detail:'Check the submitted account details.');
  return data;
}
export function UsersPage(){
  const user=useWorkspaceUser();
  const [accounts,setAccounts]=useState<Account[]>([]);
  const [username,setUsername]=useState('');const [password,setPassword]=useState('');
  const [error,setError]=useState('');const [notice,setNotice]=useState('');const [busy,setBusy]=useState(false);
  const [loading,setLoading]=useState(true);const [resetId,setResetId]=useState('');const [replacement,setReplacement]=useState('');
  useEffect(()=>{let active=true;if(user?.role!=='admin')return;request('').then(rows=>{if(active)setAccounts(rows);}).catch(e=>{if(active)setError(e.message);}).finally(()=>{if(active)setLoading(false);});return()=>{active=false;};},[user?.role]);
  async function mutate(path:string,method:string,body:object,message:string){
    setBusy(true);setError('');setNotice('');
    try{await request(path,{method,headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});setAccounts(await request(''));setNotice(message);return true;}
    catch(e){setError(e instanceof Error?e.message:'Account update failed.');return false;}finally{setBusy(false);}
  }
  async function create(event:FormEvent){event.preventDefault();if(await mutate('','POST',{username,password},'User created. Share the credentials privately with that user.')){setUsername('');setPassword('');}}
  async function reset(event:FormEvent){event.preventDefault();if(await mutate('/'+resetId,'PATCH',{password:replacement},'Password reset. Existing sessions have been revoked.')){setResetId('');setReplacement('');}}
  if(user?.role!=='admin')return <div className="page-container"><h1>Administrator access required</h1><p>Only the configured administrator can manage accounts.</p></div>;
  return <div className="page-container"><div className="page-header"><div><h1 className="page-title">Users</h1><p className="page-subtitle">Create normal accounts. Every account has its own scans, inventory and exports.</p></div></div>
    {error&&<p role="alert" className="error-banner">{error}</p>}{notice&&<p role="status">{notice}</p>}
    <section className="panel"><h2>Add user</h2><form className="account-form" onSubmit={create}>
      <label>Username<input autoComplete="off" required minLength={3} maxLength={80} value={username} onChange={e=>setUsername(e.target.value)}/></label>
      <label>Password (15–128 characters)<input type="password" autoComplete="new-password" required minLength={15} maxLength={128} value={password} onChange={e=>setPassword(e.target.value)}/></label>
      <button className="btn btn-primary" disabled={busy} type="submit">Create user</button>
    </form></section>
    <section className="panel"><h2>Accounts</h2>{loading?<p role="status">Loading accounts...</p>:<div className="account-list">{accounts.map(account=><article className="account-row" key={account.id}><div><strong>{account.username}</strong><p>{account.role} · {account.active?'Active':'Disabled'}{account.source==='env'?' · Credentials managed in .env':''}</p></div>{account.role!=='admin'&&<div className="account-actions"><button className="btn btn-secondary" disabled={busy} onClick={()=>void mutate('/'+account.id,'PATCH',{active:!account.active},account.active?'User disabled; sessions revoked.':'User enabled.')}>{account.active?'Disable':'Enable'}</button>{account.source!=='env'&&<button className="btn btn-secondary" disabled={busy} onClick={()=>{setResetId(account.id);setReplacement('');}}>Reset password</button>}</div>}</article>)}</div>}</section>
    {resetId&&<section className="panel"><h2>Reset password for {accounts.find(a=>a.id===resetId)?.username}</h2><form className="account-form" onSubmit={reset}><label>New password<input type="password" autoComplete="new-password" required minLength={15} maxLength={128} value={replacement} onChange={e=>setReplacement(e.target.value)}/></label><button className="btn btn-primary" disabled={busy}>Save password</button><button className="btn btn-secondary" type="button" onClick={()=>{setResetId('');setReplacement('');}}>Cancel</button></form></section>}
  </div>;
}
