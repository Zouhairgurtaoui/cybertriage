import React, {createContext, useCallback, useContext, useEffect, useMemo, useRef, useState} from "react";
import {ApiClient} from "../api/client.js";

const Context = createContext(null);
const IDLE = 15 * 60 * 1000;
export function SessionProvider({children}) {
  const client = useRef(null);
  if (!client.current) client.current = new ApiClient();
  const api = client.current;
  const [identity, setIdentity] = useState(null), [message, setMessage] = useState("");
  const lastActivity = useRef(Date.now());
  const logout = useCallback((reason = "") => { api.clear(); setIdentity(null); setMessage(reason); }, [api]);
  useEffect(() => {
    api.onUnauthorized = () => logout("Your analyst credential is invalid, expired or revoked.");
    return () => { api.onUnauthorized = () => {}; };
  }, [api, logout]);
  useEffect(() => {
    if (!identity) return;
    const expired = () => Date.now() - lastActivity.current >= IDLE;
    const activity = () => { if (expired()) logout("Workspace locked after inactivity."); else lastActivity.current = Date.now(); };
    const resumed = () => { if (!document.hidden && expired()) logout("Workspace locked after inactivity."); };
    const leaving = () => logout();
    for (const type of ["pointerdown", "keydown", "wheel"]) window.addEventListener(type, activity, {passive: true});
    document.addEventListener("visibilitychange", resumed);
    window.addEventListener("pagehide", leaving);
    const timer = setInterval(() => { if (expired()) logout("Workspace locked after inactivity."); }, 15000);
    return () => {
      for (const type of ["pointerdown", "keydown", "wheel"]) window.removeEventListener(type, activity);
      document.removeEventListener("visibilitychange", resumed); window.removeEventListener("pagehide", leaving); clearInterval(timer);
    };
  }, [identity, logout]);
  const login = useCallback(async token => {
    setMessage("");
    const result = await api.connect(token);
    lastActivity.current = Date.now(); setIdentity(result);
  }, [api]);
  const value = useMemo(() => ({api, identity, login, logout, message,
    global: identity?.case_ids?.length === 1 && identity.case_ids[0] === "*",
    can: permission => Boolean(identity?.permissions?.includes(permission)),
  }), [api, identity, login, logout, message]);
  return <Context.Provider value={value}>{children}</Context.Provider>;
}
export const useSession = () => useContext(Context);
