import React from "react";
import {useResource} from "../hooks/useData.js";
import {Alert,Details,ErrorState,Loading,SectionHeading} from "../components/UI.jsx";

export function Quality(){
  const resource=useResource("/api/v1/triage/evaluation");
  if(resource.loading)return <Loading/>;
  if(resource.error)return <ErrorState error={resource.error} retry={resource.reload}/>;
  const data=resource.data,m=data.overall;
  const rate=name=>m[name]===null||m[name]===undefined?"Not measured":`${(Number(m[name])*100).toFixed(1)}%`;
  const metrics=[["Retained alerts",m.alert_count],["Label coverage",rate("label_coverage")],["Suppression precision · reviewed",rate("reviewed_suppression_precision")],["Malicious suppression rate",rate("malicious_suppression_rate")]];
  return <><SectionHeading title="Triage quality" subtitle={data.basis} actions={<button className="button" onClick={resource.reload}>Refresh</button>}/><div className="metrics">{metrics.map(([label,value])=><div className="metric" key={label}><span>{label}</span><strong>{value}</strong><small>Based on retained analyst labels</small></div>)}</div>{m.suppressed_malicious_count>0&&<Alert error>{m.suppressed_malicious_count} reviewed malicious alerts were initially suppressed. Review the affected policy rules.</Alert>}<section className="panel"><h2>Interpretation limits</h2><ul className="reference-list">{data.limitations.map(value=><li key={value}>{value}</li>)}</ul><Details title="Overall metrics" value={m}/><Details title="By policy revision" value={data.by_policy_revision}/></section></>;
}
