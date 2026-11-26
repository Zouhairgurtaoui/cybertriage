import React, {createContext, useContext, useEffect, useId, useRef, useState} from "react";
import {useSession} from "../auth/Session.jsx";
import {Alert} from "./UI.jsx";

const Context=createContext(null);
export function DialogProvider({children}) {
  const [spec,setSpec]=useState(null);
  const serial=useRef(0);
  const value={show:(title,content)=>setSpec({title,content,id:++serial.current}),form:config=>setSpec({...config,form:true,id:++serial.current}),close:()=>setSpec(null)};
  return <Context.Provider value={value}>{children}{spec && <Dialog key={spec.id} spec={spec} close={()=>setSpec(null)}/>}</Context.Provider>;
}
export const useDialog=()=>useContext(Context);
function Dialog({spec,close}) {
  const {logout}=useSession(), ref=useRef(null), alive=useRef(true), prefix=useId();
  const [busy,setBusy]=useState(false),[error,setError]=useState(null),[frozen,setFrozen]=useState(false);
  useEffect(()=>{alive.current=true;ref.current.showModal();return()=>{alive.current=false;ref.current?.close();};},[]);
  async function submit(event) {
    event.preventDefault(); if (busy || frozen) return;
    const values=Object.fromEntries(new FormData(event.currentTarget));
    setBusy(true);setError(null);
    try {
      const result=await spec.submit(values);
      if (!alive.current) return;
      close(); if (spec.after) await spec.after(result);
    } catch (failure) { if (alive.current && failure.name!=="AbortError") {setError(failure);setFrozen(Boolean(failure.uncertain || failure.status===409));} }
    finally {if(alive.current)setBusy(false);}
  }
  return <dialog ref={ref} aria-labelledby={`${prefix}-title`} onCancel={event=>{event.preventDefault();if(!busy)close();}}>
    <header className="modal-head"><h2 id={`${prefix}-title`}>{spec.title}</h2><div className="actions"><button className="button small" onClick={()=>logout()}>Lock</button><button className="button small" disabled={busy} onClick={close}>Close</button></div></header>
    <div className="modal-body">{spec.description && <p className="muted">{spec.description}</p>}{spec.summary && <div className="modal-summary">{spec.summary}</div>}
      {spec.form ? <form onSubmit={submit} autoComplete="off"><fieldset disabled={busy||frozen}>
        {spec.fields.map(field=><label className={`field ${field.type==="checkbox"?"checkbox":""}`} htmlFor={`${prefix}-${field.name}`} key={field.name}>
          {field.type!=="checkbox" && <span>{field.label}</span>}
          {field.type==="select" ? <select id={`${prefix}-${field.name}`} name={field.name} defaultValue={field.value ?? ""} required={field.required!==false}>
            {field.value===undefined && <option value="" disabled>Choose an option…</option>}{field.options.map(option=>{const [value,label]=Array.isArray(option)?option:[option,String(option).replaceAll("_"," ")];return <option value={value} key={value}>{label}</option>;})}
          </select> : field.type==="textarea" ? <textarea id={`${prefix}-${field.name}`} name={field.name} rows={3} defaultValue={field.value || ""} maxLength={field.maxLength||4000} required={field.required!==false}/>
            : <input id={`${prefix}-${field.name}`} name={field.name} type={field.type||"text"} defaultValue={field.type==="checkbox"?"yes":field.value} min={field.min} max={field.max} step={field.type==="number"?1:undefined} maxLength={field.maxLength||4000} required={field.required!==false}/>}
          {field.type==="checkbox" && <span>{field.label}</span>}{field.hint && <small>{field.hint}</small>}
        </label>)}
      </fieldset>{error && <Alert error>{error.message}{error.status===409 && " Close and refresh the case."}{error.uncertain && " Check saved state before submitting another operation."}</Alert>}
        <footer className="modal-footer"><button className="button" type="button" disabled={busy} onClick={close}>{frozen?"Close and inspect saved state":"Cancel"}</button><button className={`button ${spec.danger?"danger":"primary"}`} type="submit" disabled={busy||frozen}>{busy?"Submitting…":spec.submitLabel||"Save"}</button></footer>
      </form> : spec.content}
    </div>
  </dialog>;
}
export const reasonField=()=>({name:"reason",label:"Reason",type:"textarea"});
export const supportField=(value="")=>({name:"support",label:"Supporting alert record IDs",type:"textarea",value,hint:"Active attached CyberTriage record IDs, separated by commas or new lines."});
