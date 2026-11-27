import React from "react";
import {Alert,Badge,Details,Reference} from "../components/UI.jsx";
import {parsed,stamp} from "../lib/format.js";

export function AgentReport({data}){
  const report=data.report,result=report.result;
  return <><Alert>Model analysis is provisional. References supply background guidance, not additional incident facts.</Alert><small className="muted">Completed {stamp(report.completed_at)}</small><pre className="report-text">{result.analysis||"No analysis text was stored."}</pre><h3>Retrieved references</h3>
    {(result.references||[]).length?<ol className="reference-list">{result.references.map((ref,index)=><li key={`${ref.chunk_id}:${index}`}><Reference title={ref.title} url={ref.source_url}/><small className="table-subtitle mono">{ref.chunk_id}</small>{ref.provenance_json&&<Details title="Retrieval provenance" value={parsed(ref.provenance_json)}/>}</li>)}</ol>:<p className="muted">No references were retained.</p>}
    <h3>Investigation tool evidence</h3>{(result.tool_executions||[]).length?result.tool_executions.map((tool,index)=><article className="list-card" key={`${tool.call_id}:${index}`}><div className="actions"><strong>{tool.tool_name}</strong><Badge value={tool.status}/></div><Details title="Requested arguments" value={parsed(tool.arguments_json)}/><Details title="Returned evidence" value={parsed(tool.result_json)}/></article>):<p className="muted">No model tool requests were retained.</p>}
    <Details title="Input-alert coverage" value={data.coverage}/><Details title="Input evidence" value={report.evidence}/><Details title="Investigation objective and scope" value={{task:result.investigation_task,scope:parsed(result.investigation_scope_json)}}/>
  </>;
}
