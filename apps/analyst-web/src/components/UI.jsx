import React from "react";
import {words} from "../lib/format.js";

const tones = {critical:"red",high:"amber",medium:"blue",low:"neutral",confirmed_compromise:"red",unconfirmed:"amber",benign:"green",completed:"green",succeeded:"green",approved:"blue",unknown:"amber",failed:"red",running:"blue",pending:"amber",proposed:"amber",hypothesis:"amber",observed:"blue",analyst_assessed:"purple",open:"blue",investigating:"amber",resolved:"green"};
export function Badge({value}) { return <span className={`badge ${tones[value] || "neutral"}`}>{words(value)}</span>; }
export function Json({value}) { return <pre className="code-block">{JSON.stringify(value, null, 2)}</pre>; }
export function Details({title, value}) { return <details><summary>{title}</summary>{typeof value === "string" ? <pre className="code-block">{value}</pre> : <Json value={value} />}</details>; }
export function Empty({title, children}) { return <div className="empty-state"><h3>{title}</h3><p>{children}</p></div>; }
export function Loading() { return <p className="loading" role="status">Loading retained data…</p>; }
export function Alert({children, error = false}) { return <div className={`notice ${error ? "error" : ""}`} role={error ? "alert" : "status"}>{children}</div>; }
export function ErrorState({error, retry}) { return <Alert error>{error.message}{error.status === 409 && " Refresh before making another decision."}{retry && <button className="button small" onClick={retry}>Refresh</button>}</Alert>; }
export function SectionHeading({title, subtitle, actions}) { return <div className="section-heading"><div><h2>{title}</h2>{subtitle && <p className="muted">{subtitle}</p>}</div><div className="actions">{actions}</div></div>; }
export function DataList({values}) { return <dl className="definition-list">{Object.entries(values).map(([name, value]) => <React.Fragment key={name}><dt>{name}</dt><dd>{value ?? "Unavailable"}</dd></React.Fragment>)}</dl>; }
export function Table({headers, children}) { return <div className="table-wrap"><table><thead><tr>{headers.map(value => <th key={value} scope="col">{value}</th>)}</tr></thead><tbody>{children}</tbody></table></div>; }
export function PageFooter({resource}) { return <>{resource.error && <ErrorState error={resource.error} retry={resource.reload}/>}<div className="pagination"><span>{resource.rows.length} loaded{resource.rows.length>=resource.maximum?" · display limit reached":""}</span>{resource.hasMore && <button className="button small" onClick={resource.more} disabled={resource.loading}>{resource.loading?"Loading…":"Load more"}</button>}</div></>; }
export function Reference({title, url}) {
  try { const value = new URL(url); if (value.protocol !== "https:" || value.username || value.password || value.href.length > 2048) throw new Error(); return <a href={value.href} target="_blank" rel="noopener noreferrer" referrerPolicy="no-referrer">{title}</a>; }
  catch { return <span>{title} · source URL unavailable</span>; }
}
export function Icon({name}) {
  const paths = {cases:<><rect x="3" y="3" width="7" height="7" rx="1"/><rect x="14" y="3" width="7" height="7" rx="1"/><rect x="3" y="14" width="7" height="7" rx="1"/><rect x="14" y="14" width="7" height="7" rx="1"/></>,
    alerts:<><path d="M5 17h14l-2-3V9a5 5 0 0 0-10 0v5z"/><path d="M10 21h4"/></>,
    quality:<><path d="M4 20V10m8 10V4m8 16v-7"/><path d="M2 21h20"/></>,
    lock:<><rect x="5" y="10" width="14" height="11" rx="2"/><path d="M8 10V6a4 4 0 0 1 8 0v4"/></>};
  return <svg className="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6" aria-hidden="true">{paths[name] || paths.cases}</svg>;
}
