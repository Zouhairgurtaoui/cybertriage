import React, {useCallback, useState} from "react";
import {useSession} from "./auth/Session.jsx";
import {DialogProvider} from "./components/ActionDialog.jsx";
import {Alert, Icon} from "./components/UI.jsx";
import {CaseList, CaseWorkspace} from "./features/Cases.jsx";
import {AlertInbox} from "./features/Alerts.jsx";
import {AgentReviews} from "./features/AgentReviews.jsx";
import {Quality} from "./features/Quality.jsx";

function Login() {
  const {login,message}=useSession();
  const [token,setToken]=useState(""),[busy,setBusy]=useState(false),[error,setError]=useState("");
  async function submit(event){event.preventDefault();const value=token;setToken("");setBusy(true);setError("");try{await login(value);}catch(failure){if(failure.name!=="AbortError")setError(failure.message);}finally{setBusy(false);}}
  return <main className="login-page"><section className="login-card"><div className="brand"><span className="brand-mark">CT</span><div>CyberTriage<small>Analyst console</small></div></div><h1>Analyst access</h1><p className="muted">Connect with your assigned credential. Access to evidence and response actions follows your analyst permissions.</p>
    <form onSubmit={submit} autoComplete="off"><label className="field">Access token<input type="password" autoComplete="off" spellCheck={false} value={token} onChange={event=>setToken(event.target.value)} minLength={32} maxLength={512} required/></label><button type="submit" className="button primary wide" disabled={busy}>{busy?"Connecting…":"Connect"}</button></form>
    {(error||message)&&<Alert error>{error||message}</Alert>}<p className="login-footnote">Credentials stay in page memory. Locking, reloading or inactivity ends this browser session.</p></section></main>;
}
function Console() {
  const {identity,can,global,logout}=useSession();
  const [route,setRoute]=useState({view:"cases"}),[notice,setNotice]=useState(null);
  const notify=useCallback((text,error=false)=>setNotice({text,error}),[]);
  const navigate=useCallback(value=>{setNotice(null);setRoute(value);},[]);
  const page=route.view==="case"?"cases":route.view;
  const nav=[["cases","Cases"],["reviews","Agent review"],["alerts","Alert inbox"],["quality","Triage quality"]].filter(([name])=>(name==="cases"||name==="reviews")||(global&&(name==="alerts"?can("cases:read"):can("triage:review"))));
  return <DialogProvider><a className="skip-link" href="#workspace-main">Skip to workspace</a><div className="workspace"><aside className="sidebar"><div className="brand"><span className="brand-mark">CT</span><div>CyberTriage<small>Analyst console</small></div></div><div className="nav-caption">Workspace</div><nav aria-label="Workspace navigation">{nav.map(([name,label])=><button key={name} className={`nav-item ${page===name?"active":""}`} aria-current={page===name?"page":undefined} onClick={()=>navigate({view:name})}><Icon name={name}/>{label}</button>)}</nav><div className="sidebar-context"><strong>Evidence before action</strong><p>Model reports require review. Authorization remains an explicit analyst decision.</p></div><div className="sidebar-user"><strong>{identity.analyst_id}</strong><small>{global?"Global evidence scope":`${identity.case_ids.length} assigned case scopes`}</small></div></aside>
    <div className="workspace-body"><header className="topbar"><div><span className="muted">Workspace</span><span aria-hidden="true">/</span><strong>{route.view==="case"?"Case review":nav.find(([name])=>name===page)?.[1]||"Cases"}</strong></div><button className="button small" onClick={()=>logout()}><Icon name="lock"/>Lock</button></header>
      <main id="workspace-main" tabIndex={-1}>{notice&&<Alert error={notice.error}>{notice.text}</Alert>}{route.view==="reviews"?<AgentReviews key={route.alertId||"all"} alertId={route.alertId} navigate={navigate}/>:route.view==="alerts"?<AlertInbox navigate={navigate} notify={notify}/>:route.view==="quality"?<Quality/>:route.view==="case"?<CaseWorkspace key={route.caseId} caseId={route.caseId} navigate={navigate} notify={notify}/>:<CaseList navigate={navigate}/>}</main><footer className="workspace-footer">CyberTriage <span>Retained evidence · Attributed decisions · Explicit authorization</span></footer>
    </div></div></DialogProvider>;
}
export default function App(){const{identity}=useSession();return identity?<Console/>:<Login/>;}
