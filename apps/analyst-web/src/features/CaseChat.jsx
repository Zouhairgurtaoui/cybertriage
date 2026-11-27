import React,{useEffect,useRef,useState} from "react";
import {useSession} from "../auth/Session.jsx";
import {useAlive,usePaged} from "../hooks/useData.js";
import {useDialog} from "../components/ActionDialog.jsx";
import {Alert,Badge,Empty,ErrorState,Loading,SectionHeading} from "../components/UI.jsx";
import {caseUrl,key,short,stamp} from "../lib/format.js";
import {AgentReport} from "./AgentReport.jsx";

export function CaseChat({context:ctx}) {
  const {api,can,global}=useSession(),dialog=useDialog(),alive=useAlive();
  const allowed=global&&can("reports:read_all");
  const thread=usePaged(allowed?caseUrl(ctx.caseId,"/conversation"):null,"turns",{next:"next_before",parameter:"before",pageSize:20,maximum:1000});
  const evidence=usePaged(allowed?caseUrl(ctx.caseId,"/sections/alerts"):null,"alerts");
  const [content,setContent]=useState(""),[mode,setMode]=useState("review"),[anchor,setAnchor]=useState("");
  const [busy,setBusy]=useState(false),[error,setError]=useState(null),[uncertain,setUncertain]=useState(false);
  const submission=useRef(null),sending=useRef(false),scroll=useRef(null),follow=useRef(true);
  const rows=[...thread.rows].sort((a,b)=>a.seq-b.seq),pending=rows.find(row=>["pending","running"].includes(row.status));
  const attachments=evidence.rows.filter(row=>row.active);
  const latest=rows.at(-1),bodyBytes=new TextEncoder().encode(content).length;
  useEffect(()=>{if(follow.current&&scroll.current)scroll.current.scrollTop=scroll.current.scrollHeight;},[latest?.turn_id,latest?.status,latest?.answer]);
  useEffect(()=>{
    if(!pending)return;
    const controller=new AbortController();let inFlight=false;
    const timer=setInterval(async()=>{
      if(inFlight||document.hidden)return;inFlight=true;
      try{
        const result=await api.request(caseUrl(ctx.caseId,`/conversation/${encodeURIComponent(pending.turn_id)}`),{signal:controller.signal});
        if(!controller.signal.aborted&&alive.current){thread.reload();if(!["pending","running"].includes(result.turn.status))ctx.refresh();}
      }catch(failure){if(!controller.signal.aborted&&alive.current)setError(failure);}
      finally{inFlight=false;}
    },8000);
    return()=>{clearInterval(timer);controller.abort();};
  },[api,ctx.caseId,pending?.turn_id,thread.reload,ctx.refresh,alive]);
  async function send(event){
    event?.preventDefault();if(sending.current||pending||!can("investigations:request")||!ctx.editable)return;
    const saved=submission.current||{content:content.trim(),expected_version:thread.version??ctx.incident.version,idempotency_key:key(),mode,anchor_alert_id:anchor||null};
    if(!saved.content)return;
    submission.current=saved;sending.current=true;setBusy(true);setError(null);
    try{
      await api.request(caseUrl(ctx.caseId,"/conversation"),{method:"POST",body:saved});
      if(alive.current){submission.current=null;setUncertain(false);setContent("");follow.current=true;thread.reload();ctx.refresh();}
    }catch(failure){
      if(alive.current){setError(failure);setUncertain(Boolean(failure.uncertain));if(!failure.uncertain)submission.current=null;if(failure.status===409){thread.reload();ctx.refresh();}}
    }finally{sending.current=false;if(alive.current)setBusy(false);}
  }
  async function sources(turnId){
    try{const result=await api.request(caseUrl(ctx.caseId,`/conversation/${encodeURIComponent(turnId)}`));if(alive.current&&result.report)dialog.show("Reply evidence and sources",<AgentReport data={result}/>);}
    catch(failure){if(alive.current)setError(failure);}
  }
  if(!allowed)return <Empty title="Conversation access restricted">Case conversations require global evidence scope and reports:read_all permission.</Empty>;
  return <section className="case-chat panel"><SectionHeading title="Case conversation" subtitle="Discuss this case with the investigation agent. Replies and their evidence are retained." actions={<><button className="button small" onClick={()=>{thread.reload();evidence.reload();ctx.refresh();}}>Refresh</button><button className="button small" onClick={()=>ctx.openSection("evidence")}>Evidence</button><button className="button small" onClick={()=>ctx.openSection("responses")}>Responses</button></>}/>
    <div className="chat-thread" ref={scroll} onScroll={event=>{const node=event.currentTarget;follow.current=node.scrollHeight-node.scrollTop-node.clientHeight<80;}} aria-label="Case conversation">
      {thread.hasMore&&<button className="button small" disabled={thread.loading} onClick={()=>{follow.current=false;thread.more();}}>Load older messages</button>}
      {thread.loading&&!rows.length?<Loading/>:!rows.length&&!thread.error?<div className="chat-welcome"><h3>Review this case with the agent</h3><p>Describe what happened, ask a question, or attach Wazuh alerts from Evidence. Existing saved reports are background context; this starts a new conversation.</p><button className="button" onClick={()=>setContent("Review the available evidence for this case. Explain the observed facts, possible explanations, missing evidence and the next investigation steps.")}>Prepare a case review</button></div>:rows.map(turn=><React.Fragment key={turn.turn_id}>
        <article className="chat-message analyst"><header><strong>{turn.actor}</strong><time>{stamp(turn.created_at)}</time></header><div className="chat-text">{turn.content}</div><small>{turn.mode==="investigate"?"Read-only investigation":"Review"} · Case snapshot v{turn.case_version}{turn.anchor_alert_id&&` · Anchor ${short(turn.anchor_alert_id,12)}`}</small></article>
        <article className="chat-message agent"><header><strong>CyberTriage agent</strong><Badge value={turn.status}/></header>{turn.answer?<><div className="chat-text">{turn.answer}</div><div className="chat-reply-meta"><span>Provisional · {turn.input_alert_ids.length} retained input alerts</span>{Boolean(turn.history_omitted)&&<span>Some prior context was omitted</span>}<button className="link-button" onClick={()=>sources(turn.turn_id)}>Evidence and sources</button></div></>:<p className="muted">{turn.status==="failed"?"The agent could not finish this reply. Please send your message again.":turn.status==="running"?"The agent is reviewing the case. You can leave and return to this conversation.":"Waiting for the case chat worker. Replies appear here after processing."}</p>}</article>
      </React.Fragment>)}
    </div>
    {thread.error&&<ErrorState error={thread.error} retry={thread.reload}/>}
    <form className="chat-composer" onSubmit={send}>
      <div className="chat-options"><label>Mode<select value={mode} disabled={busy||uncertain||Boolean(pending)} onChange={event=>setMode(event.target.value)}><option value="review">Discuss / review</option><option value="investigate" disabled={!attachments.length}>Investigate with read-only tools</option></select></label><label>Evidence focus<select value={anchor} disabled={busy||uncertain||Boolean(pending)} onChange={event=>setAnchor(event.target.value)}><option value="">All attached alerts (up to five)</option>{attachments.map(row=><option key={row.alert_record_id} value={row.alert_record_id}>{row.agent_name||"Alert"} · {short(row.alert_record_id,16)}</option>)}</select></label>{evidence.hasMore&&<button className="button small" type="button" onClick={evidence.more}>More attached alerts</button>}</div>
      {evidence.error&&<ErrorState error={evidence.error} retry={evidence.reload}/>}
      <label className="field" htmlFor="case-chat-message">Message to the agent<textarea id="case-chat-message" rows={3} maxLength={2000} placeholder="Describe the incident or ask what to investigate next…" value={content} disabled={busy||uncertain||!ctx.editable||!can("investigations:request")} onChange={event=>setContent(event.target.value)} onKeyDown={event=>{if(event.key==="Enter"&&!event.shiftKey&&!event.nativeEvent.isComposing){event.preventDefault();if(bodyBytes<=3000)send();}}}/></label>
      {error&&<Alert error>{error.message}{uncertain&&" Retry the same submission to check its saved outcome without creating another turn."}</Alert>}
      <div className="chat-compose-footer"><small>{pending?"One reply is in progress for this case.":"Enter to send · Shift+Enter for a new line"} · {bodyBytes}/3000 bytes</small><button className="button primary" type="submit" disabled={busy||Boolean(pending)||!ctx.editable||!can("investigations:request")||(!uncertain&&(!content.trim()||bodyBytes>3000))}>{busy?"Sending…":uncertain?"Retry same submission":"Send message"}</button></div>
      <p className="chat-footnote">Chat cannot execute firewall commands or approve responses. Use Responses for the proposal and approval workflow.</p>
    </form>
  </section>;
}
