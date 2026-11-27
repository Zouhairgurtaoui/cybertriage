import React from "react";
import {useSession} from "../auth/Session.jsx";
import {useAlive,usePaged} from "../hooks/useData.js";
import {useDialog,reasonField} from "../components/ActionDialog.jsx";
import {Badge,DataList,Details,Empty,ErrorState,Loading,PageFooter,SectionHeading,Table} from "../components/UI.jsx";
import {caseUrl,short,stamp} from "../lib/format.js";

export function AlertInbox({navigate,notify}) {
  const {api,global,can}=useSession(),dialog=useDialog();
  const alive=useAlive();
  const resource=usePaged(global&&can("cases:read")?"/api/v1/alerts":null,"alerts",{next:"next_before",parameter:"before"});
  async function inspect(recordId){
    try{
      const data=await api.request(`/api/v1/alerts/${encodeURIComponent(recordId)}`);
      if(!alive.current)return;
      dialog.show("Retained alert",<><DataList values={{"Record ID":data.record_id,"Wazuh source ID":data.alert.source_alert_id,"Manager":data.alert.source_instance,"Host":data.alert.agent_name,"Event time":stamp(data.alert.timestamp),"Payload SHA-256":data.payload_sha256}}/>
        {can("reports:read_all")&&<button className="button" onClick={()=>{dialog.close();navigate({view:"reviews",alertId:recordId});}}>Read saved reports</button>}<Details title="Analysis job" value={data.analysis_job}/>{can("cases:write")&&<button className="button primary" onClick={()=>attach(recordId)}>Attach to a case</button>}<Details title="Normalized evidence" value={data.alert}/><Details title="Latest triage decision" value={data.latest_triage}/></>);
    }catch(error){if(error.name!=="AbortError")notify(error.message,true);}
  }
  async function attach(recordId){
    try{
      const result=await api.request("/api/v1/cases?limit=100");const cases=result.cases.filter(row=>!["closed","resolved"].includes(row.status));
      if(!alive.current)return;
      if(!cases.length){dialog.show("No editable case",<Empty title="Open or reopen a case first">Attach this alert after defining its investigation scope.</Empty>);return;}
      dialog.form({title:"Attach retained alert",description:"Membership establishes an investigation scope, not a common attacker.",fields:[{name:"case_id",label:"Case",type:"select",options:cases.map(row=>[row.case_id,row.title])},reasonField()],submit:values=>api.request(caseUrl(values.case_id,"/alerts"),{method:"POST",body:{alert_ids:[recordId],reason:values.reason}}),submitLabel:"Attach alert",after:result=>navigate({view:"case",caseId:result.case.case_id})});
    }catch(error){if(error.name!=="AbortError")notify(error.message,true);}
  }
  if(!global||!can("cases:read"))return <Empty title="Inbox access restricted">Global evidence access is required to browse retained alerts.</Empty>;
  return <><SectionHeading title="Alert inbox" subtitle="Retained Wazuh alerts. Newest local arrivals are shown first; event time is separate." actions={<button className="button" onClick={resource.reload}>Refresh</button>}/><section className="panel">
    {resource.loading&&!resource.rows.length?<Loading/>:!resource.rows.length&&!resource.error?<Empty title="No retained alerts">Check ingestion and the Wazuh integration. This view does not generate example alerts.</Empty>:<Table headers={["Alert","Host","Level","Triage / job","Event time"]}>{resource.rows.map(row=><tr key={row.record_id}><td><button className="link-button table-title" onClick={()=>inspect(row.record_id)}>{row.description||"Retained alert"}</button><small className="table-subtitle mono">{short(row.record_id,22)}</small><small className="table-subtitle">{row.event?.event_id??"No event ID"} · {row.source_instance}</small></td><td>{row.agent_name}</td><td>{row.rule_level}</td><td><div className="stack compact"><Badge value={row.triage_action||"untriaged"}/><Badge value={row.job_status||"no automatic job"}/>{can("reports:read_all")&&<button className="link-button" onClick={()=>navigate({view:"reviews",alertId:row.record_id})}>Saved reports</button>}</div></td><td>{stamp(row.event_time)}</td></tr>)}</Table>}
    <PageFooter resource={resource}/></section></>;
}
