import React,{useEffect} from "react";
import {useSession} from "../auth/Session.jsx";
import {usePaged} from "../hooks/useData.js";
import {useDialog} from "../components/ActionDialog.jsx";

export function CaseHistory({navigate,caseId}) {
  const {api,can,global}=useSession(),dialog=useDialog();
  const resource=usePaged(can("cases:read")?"/api/v1/cases":null,"cases");
  useEffect(()=>{resource.reload();},[caseId,resource.reload]);
  const cases=[...resource.rows].sort((a,b)=>b.updated_at.localeCompare(a.updated_at)).slice(0,12);
  function create(){dialog.form({title:"New case conversation",description:"Describe the case now; retained alerts can be attached from Evidence.",fields:[{name:"title",label:"Case title",maxLength:200},{name:"description",label:"Reported context",type:"textarea",required:false,maxLength:8000}],submit:values=>api.request("/api/v1/cases",{method:"POST",body:{...values,priority:"medium"}}),submitLabel:"Create and open chat",after:result=>{resource.reload();navigate({view:"case",caseId:result.case_id});}});}
  if(!can("cases:read"))return null;
  return <section className="case-history" aria-label="Case conversations"><div className="case-history-heading"><span>Case conversations</span>{global&&can("cases:write")&&<button onClick={create} aria-label="New case conversation" title="New case conversation">+</button>}</div>{resource.error?<button className="case-history-link" onClick={resource.reload}>Could not load cases · Retry</button>:cases.map(incident=><button key={incident.case_id} className={`case-history-link ${caseId===incident.case_id?"active":""}`} aria-current={caseId===incident.case_id?"page":undefined} onClick={()=>navigate({view:"case",caseId:incident.case_id})} title={incident.title}>{incident.title}</button>)}{!cases.length&&!resource.loading&&!resource.error&&<small>No cases yet</small>}<button className="case-history-link all" onClick={()=>navigate({view:"cases"})}>Browse all cases</button></section>;
}
