import {useCallback, useEffect, useRef, useState} from "react";
import {useSession} from "../auth/Session.jsx";
import {ApiError} from "../api/client.js";
import {query} from "../lib/format.js";

export function useAlive(){const ref=useRef(true);useEffect(()=>{ref.current=true;return()=>{ref.current=false;};},[]);return ref;}
export function useVersion(resource,context){useEffect(()=>{if(resource.error?.status===409||(resource.version!==null&&resource.version!==undefined&&resource.version!==context.incident.version))context.markStale();},[resource.error,resource.version,context.incident.version,context.markStale]);}

export function useResource(path) {
  const {api} = useSession();
  const [nonce, setNonce] = useState(0), [state, setState] = useState({data:null, error:null, loading:true});
  const lastPath=useRef(null);
  useEffect(() => {
    if (!path) { setState({data:null,error:null,loading:false}); return; }
    const controller = new AbortController(); let active = true;
    const samePath=lastPath.current===path;lastPath.current=path;
    setState(old=>({data:samePath?old.data:null,error:null,loading:true}));
    api.request(path, {signal: controller.signal}).then(data => { if (active) setState({data,error:null,loading:false}); }, error => { if (active && error.name !== "AbortError") setState({data:null,error,loading:false}); });
    return () => { active = false; controller.abort(); };
  }, [api, path, nonce]);
  return {...state, reload: useCallback(() => setNonce(value => value + 1), [])};
}

export function usePaged(path, key, {next="next_after", parameter="after", maximum=500, pageSize=50} = {}) {
  const {api} = useSession();
  const [nonce, setNonce] = useState(0), [state, setState] = useState({rows:[],cursor:null,loading:true,error:null,version:null});
  const generation = useRef(0), busy = useRef(false), controller = useRef(null), current = useRef(state);
  current.current = state;
  const load = useCallback(async (cursor, append, own) => {
    if (!path || busy.current) return;
    busy.current = true; const request = new AbortController(); controller.current = request;
    setState(old => ({...old,loading:true,error:null}));
    try {
      const data = await api.request(`${path}${path.includes("?") ? "&" : "?"}${query({limit:pageSize,[parameter]:cursor})}`, {signal:request.signal});
      if (own !== generation.current) return;
      if (!Array.isArray(data[key])) throw new ApiError("The server returned an invalid list response. Refresh saved state.",502);
      const previous = current.current;
      if (append && previous.version !== null && data.case_version !== previous.version) throw new ApiError("Case changed while paging. Refresh this list.",409);
      setState({rows:append ? [...previous.rows,...data[key]] : data[key], cursor:data[next],loading:false,error:null,version:data.case_version ?? null});
    } catch (error) { if (own === generation.current && error.name !== "AbortError") setState(old => ({...old,loading:false,error})); }
    finally { if (own === generation.current) busy.current = false; }
  }, [api,path,key,next,parameter,pageSize]);
  useEffect(() => {
    generation.current += 1; busy.current = false; const own = generation.current;
    setState({rows:[],cursor:null,loading:Boolean(path),error:null,version:null});
    if (path) load(null,false,own);
    return () => { generation.current += 1; controller.current?.abort(); };
  }, [path,nonce,load]);
  const more = useCallback(() => { const value=current.current; if (value.cursor !== null && value.cursor !== undefined && value.rows.length < maximum) load(value.cursor,true,generation.current); }, [load,maximum]);
  return {...state, hasMore:state.cursor !== null && state.cursor !== undefined && state.rows.length < maximum,
    more, reload:useCallback(() => setNonce(value => value + 1),[]), maximum};
}
