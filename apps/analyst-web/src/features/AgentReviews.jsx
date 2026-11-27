import React,{useState} from "react";
import {useSession} from "../auth/Session.jsx";
import {usePaged,useResource} from "../hooks/useData.js";
import {Badge,Empty,ErrorState,Loading,PageFooter,SectionHeading,Table} from "../components/UI.jsx";
import {short,stamp} from "../lib/format.js";
import {AgentReport} from "./AgentReport.jsx";

export function AgentReviews({alertId,navigate}) {
  const {global,can}=useSession();
  const allowed=global&&can("reports:read_all");
  const filter=alertId?`?alert_id=${encodeURIComponent(alertId)}`:"";
  const reports=usePaged(allowed?`/api/v1/analyses${filter}`:null,"analyses",{next:"next_before",parameter:"before"});
  const [selected,setSelected]=useState(null);
  const selectedId=selected||reports.rows[0]?.analysis_id;
  const detail=useResource(allowed&&selectedId?`/api/v1/analyses/${encodeURIComponent(selectedId)}`:null);
  const alert=useResource(allowed&&alertId&&can("cases:read")?`/api/v1/alerts/${encodeURIComponent(alertId)}`:null);
  function refresh(){reports.reload();detail.reload();alert.reload();}
  if(!allowed)return <Empty title="Agent review access restricted">Global evidence scope and reports:read_all permission are required. Reports can contain evidence from related alerts.</Empty>;
  return <><SectionHeading title="Saved reports" subtitle={alertId?`Reports covering alert ${alertId}`:"Saved automatic analyses and requested investigations, newest first."} actions={<>{alertId&&<button className="button" onClick={()=>navigate({view:"reviews"})}>All reports</button>}<button className="button" onClick={refresh}>Refresh</button></>}/>
    <section className="panel"><SectionHeading title="Saved reports"/>
      {reports.loading&&!reports.rows.length?<Loading/>:!reports.rows.length&&!reports.error?<Empty title="No saved report yet">{alertId?"This alert has no saved analysis. Pending jobs need an available worker; suppressed alerts remain retained without automatic analysis.":"Reports appear after an analysis worker completes a job. Opening this page does not start an investigation."}</Empty>:<Table headers={["Report","Host","Completed · UTC","Input alerts"]}>{reports.rows.map(row=><tr key={row.analysis_id} aria-selected={selectedId===row.analysis_id}><td><button className="link-button table-title" onClick={()=>setSelected(row.analysis_id)}>{row.description||"Saved analysis"}</button><small className="table-subtitle mono">{short(row.analysis_id,22)}</small></td><td>{row.agent_name}</td><td>{stamp(row.completed_at)}</td><td>{row.covered_alert_count||"Legacy coverage"}</td></tr>)}</Table>}
      <PageFooter resource={reports}/>
      {alert.error&&<ErrorState error={alert.error} retry={alert.reload}/>}
      {alert.data&&<div className="actions"><span>Automatic analysis:</span><Badge value={alert.data.analysis_job?.status||"no automatic job"}/>{alert.data.analysis_job?.last_error_code&&<span>{alert.data.analysis_job.last_error_code}</span>}<Badge value={alert.data.latest_triage?.action||"untriaged"}/></div>}
    </section>
    {selectedId&&<section className="panel"><SectionHeading title="Investigation report" subtitle={selectedId}/>{detail.loading?<Loading/>:detail.error?<ErrorState error={detail.error} retry={detail.reload}/>:detail.data&&<AgentReport data={detail.data}/>}</section>}
  </>;
}
