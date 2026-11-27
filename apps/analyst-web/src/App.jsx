import React, {useCallback, useState} from "react";
import {useSession} from "./auth/Session.jsx";
import {DialogProvider} from "./components/ActionDialog.jsx";
import {Alert, Icon} from "./components/UI.jsx";
import {CaseList, CaseWorkspace} from "./features/Cases.jsx";
import {AlertInbox} from "./features/Alerts.jsx";
import {AgentReviews} from "./features/AgentReviews.jsx";
import {CaseHistory} from "./features/CaseHistory.jsx";
import {Quality} from "./features/Quality.jsx";

function Login() {
  const {login,loginPassword,message}=useSession();
  const [method,setMethod]=useState("password"),[username,setUsername]=useState(""),[password,setPassword]=useState("");
  const [token,setToken]=useState(""),[busy,setBusy]=useState(false),[error,setError]=useState("");
  async function submit(event){
    event.preventDefault();const secret=method==="password"?password:token;
    setPassword("");setToken("");setBusy(true);setError("");
    try{if(method==="password")await loginPassword(username.trim(),secret);else await login(secret);}
    catch(failure){if(failure.name!=="AbortError")setError(failure.message);}
    finally{setBusy(false);}
  }
  return <main className="login-page"><section className="login-card"><div className="brand"><span className="brand-mark">CT</span><div>CyberTriage<small>Analyst console</small></div></div><h1>Analyst access</h1><p className="muted">Sign in to your investigation workspace.</p>
    <div className="login-methods"><button type="button" className={`button small ${method==="password"?"primary":""}`} disabled={busy} aria-pressed={method==="password"} onClick={()=>{setMethod("password");setToken("");setError("");}}>Username and password</button><button type="button" className={`button small ${method==="token"?"primary":""}`} disabled={busy} aria-pressed={method==="token"} onClick={()=>{setMethod("token");setPassword("");setError("");}}>API token</button></div>
    <form onSubmit={submit}>{method==="password"?<><label className="field">Username<input name="username" autoComplete="username" spellCheck={false} value={username} onChange={event=>setUsername(event.target.value)} maxLength={64} required disabled={busy}/></label><label className="field">Password<input name="password" type="password" autoComplete="current-password" value={password} onChange={event=>setPassword(event.target.value)} maxLength={128} required disabled={busy}/></label></>:<label className="field">Access token<input type="password" autoComplete="off" spellCheck={false} value={token} onChange={event=>setToken(event.target.value)} minLength={32} maxLength={512} required disabled={busy}/></label>}<button type="submit" className="button primary wide" disabled={busy}>{busy?"Signing in…":"Sign in"}</button></form>
    {(error||message)&&<Alert error>{error||message}</Alert>}<p className="login-footnote">Password login creates a 15-minute session. Locking signs out that session. Credentials are not stored in browser storage.</p></section></main>;
}
function Console() {
  const {identity,can,global,logout}=useSession();
  const [route,setRoute]=useState({view:"cases"}),[notice,setNotice]=useState(null);
  const notify=useCallback((text,error=false)=>setNotice({text,error}),[]);
  const navigate=useCallback(value=>{setNotice(null);setRoute(value);},[]);
  const page=route.view==="case"?"cases":route.view;
  const nav=[["cases","Cases"],["reviews","Saved reports"],["alerts","Alert inbox"],["quality","Triage quality"]].filter(([name])=>(name==="cases"||name==="reviews")||(global&&(name==="alerts"?can("cases:read"):can("triage:review"))));
  return <DialogProvider><a className="skip-link" href="#workspace-main">Skip to workspace</a><div className="workspace"><aside className="sidebar"><div className="brand"><span className="brand-mark">CT</span><div>CyberTriage<small>Analyst console</small></div></div><div className="nav-caption">Workspace</div><nav aria-label="Workspace navigation">{nav.map(([name,label])=><button key={name} className={`nav-item ${page===name?"active":""}`} aria-current={page===name?"page":undefined} onClick={()=>navigate({view:name})}><Icon name={name}/>{label}</button>)}</nav><CaseHistory navigate={navigate} caseId={route.view==="case"?route.caseId:null}/><div className="sidebar-context"><strong>Evidence before action</strong><p>Model reports require review. Authorization remains an explicit analyst decision.</p></div><div className="sidebar-user"><strong>{identity.analyst_id}</strong><small>{global?"Global evidence scope":`${identity.case_ids.length} assigned case scopes`}</small></div></aside>
    <div className="workspace-body"><header className="topbar"><div><span className="muted">Workspace</span><span aria-hidden="true">/</span><strong>{route.view==="case"?"Case review":nav.find(([name])=>name===page)?.[1]||"Cases"}</strong></div><button className="button small" onClick={()=>logout()}><Icon name="lock"/>Lock</button></header>
      <main id="workspace-main" tabIndex={-1}>{notice&&<Alert error={notice.error}>{notice.text}</Alert>}{route.view==="reviews"?<AgentReviews key={route.alertId||"all"} alertId={route.alertId} navigate={navigate}/>:route.view==="alerts"?<AlertInbox navigate={navigate} notify={notify}/>:route.view==="quality"?<Quality/>:route.view==="case"?<CaseWorkspace key={`${route.caseId}:${route.tab||"chat"}`} initialTab={route.tab||"chat"} caseId={route.caseId} navigate={navigate} notify={notify}/>:<CaseList navigate={navigate}/>}</main><footer className="workspace-footer">CyberTriage <span>Retained evidence · Attributed decisions · Explicit authorization</span></footer>
    </div></div></DialogProvider>;
}
export default function App(){const{identity}=useSession();return identity?<Console/>:<Login/>;}
