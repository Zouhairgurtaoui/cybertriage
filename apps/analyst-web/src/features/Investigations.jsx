import React,{useEffect,useRef,useState} from "react";
import {useSession} from "../auth/Session.jsx";
import {useAlive,usePaged,useVersion} from "../hooks/useData.js";
import {useDialog} from "../components/ActionDialog.jsx";
import {Alert,Badge,Empty,Loading,PageFooter,SectionHeading,Table} from "../components/UI.jsx";
import {caseUrl,key,short,stamp} from "../lib/format.js";

import {AgentReport} from "./AgentReport.jsx";

export function Investigations({context:ctx}){
  const{api,can,global}=useSession(),dialog=useDialog(),alive=useAlive();
  const requests=usePaged(caseUrl(ctx.caseId,"/investigation-requests"),"requests",{next:"next_before",parameter:"before"});
  const reports=usePaged(global&&can("reports:read_all")?caseUrl(ctx.caseId,"/sections/investigations"):null,"investigations");useVersion(reports,ctx);
  const[updates,setUpdates]=useState({}),busy=useRef(false);
  const rows=requests.rows.map(row=>updates[row.job_id]||row),pending=rows.filter(row=>["pending","running"].includes(row.status)).slice(0,20),pendingKey=pending.map(row=>row.job_id).join(",");
  useEffect(()=>{
    if(!pendingKey)return;
    const controller=new AbortController();
    const timer=setInterval(async()=>{
      if(busy.current||document.hidden)return;busy.current=true;
      try{
        const outcomes=await Promise.allSettled(pendingKey.split(",").map(id=>api.request(caseUrl(ctx.caseId,`/investigation-requests/${encodeURIComponent(id)}`),{signal:controller.signal})));
        if(controller.signal.aborted||!alive.current)return;
        const next={};let completed=false,failed=false;
        for(const outcome of outcomes){if(outcome.status==="fulfilled"){next[outcome.value.job_id]=outcome.value;if(outcome.value.status==="completed")completed=true;}else if(outcome.reason.name!=="AbortError")failed=true;}
        setUpdates(old=>({...old,...next}));
        if(completed)ctx.markStale();
        if(failed)ctx.notify("Some request statuses could not be refreshed. Retained state has not been replaced by an assumed failure.",true);
      }finally{busy.current=false;}
    },12000);
    return()=>{clearInterval(timer);controller.abort();};
  },[api,ctx.caseId,pendingKey,ctx.markStale,ctx.notify,alive]);
  function request(){const version=ctx.incident.version,idempotency=key();dialog.form({title:"Investigate further",description:`Queue bounded read-only work from case version ${version}. Previous reports remain retained.`,fields:[{name:"anchor",label:"Active attached alert record ID",maxLength:128},{name:"task",label:"Investigation objective",type:"textarea",maxLength:1500}],submit:values=>api.request(caseUrl(ctx.caseId,"/investigation-requests"),{method:"POST",body:{alert_record_id:values.anchor,task:values.task,expected_version:version,idempotency_key:idempotency}}),submitLabel:"Queue investigation",after:ctx.refresh});}
  async function read(id){try{const data=await api.request(caseUrl(ctx.caseId,`/reports/${encodeURIComponent(id)}`));if(alive.current)dialog.show("Saved investigation report",<AgentReport data={data}/>);}catch(error){if(alive.current&&error.name!=="AbortError")ctx.notify(error.message,true);}}
  return <><section className="panel"><SectionHeading title="Saved agent reports" subtitle="Generated reports remain provisional. Original coverage and tool outputs are retained."/>
    {!global||!can("reports:read_all")?<Empty title="Full report access restricted">Reports may include related evidence outside the original attachments. Global scope and reports:read_all permission are required.</Empty>:<>{reports.loading&&!reports.rows.length?<Loading/>:!reports.rows.length&&!reports.error?<Empty title="No linked reports">Reports appear when an analysis covering attached evidence is saved.</Empty>:<Table headers={["Report","Completed · UTC","Input alerts","Search context"]}>{reports.rows.map(row=><tr key={row.analysis_id}><td><button className="link-button mono" onClick={()=>read(row.analysis_id)}>{short(row.analysis_id,22)}</button></td><td>{stamp(row.completed_at)}</td><td>{row.covered_alert_count}</td><td>{row.retrieval_query}</td></tr>)}</Table>}<PageFooter resource={reports}/></>}
    </section><section className="panel"><SectionHeading title="Requested investigations" subtitle="The separate investigation worker processes queued requests." actions={global&&can("investigations:request")&&<button className="button primary" disabled={!ctx.editable} onClick={request}>Investigate further</button>}/>
    {requests.loading&&!rows.length?<Loading/>:!rows.length&&!requests.error?<Empty title="No additional requests">Use an attached alert to anchor a new investigation.</Empty>:rows.map(row=><article className="list-card" key={row.job_id}><div className="actions"><Badge value={row.status}/><small className="muted">{row.attempt_count} attempts · {stamp(row.created_at)}</small></div><p>{row.task}</p><small className="table-subtitle mono">Request {row.job_id}</small><small className="table-subtitle mono">Anchor {row.alert_record_id}</small>{row.last_error_code&&<Alert error>{row.last_error_code}</Alert>}{row.analysis_id&&global&&can("reports:read_all")&&<button className="button small" onClick={()=>read(row.analysis_id)}>Read report</button>}</article>)}<PageFooter resource={requests}/>
    </section></>;
}
