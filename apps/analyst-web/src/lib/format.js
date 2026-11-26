export const words = value => String(value ?? "Unavailable").replaceAll("_", " ");
export const short = (value, length = 14) => String(value ?? "").length > length ? `${String(value).slice(0, length)}…` : String(value ?? "");
export function stamp(value) {
  if (!value) return "Unavailable";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? String(value) : date.toISOString().replace("T", " ").replace("Z", " UTC");
}
export function ids(value) {
  const result = [...new Set(String(value || "").split(/[\s,]+/).filter(Boolean))];
  if (result.length > 100) throw new Error("Use at most 100 alert record IDs.");
  return result;
}
export function key() {
  const bytes = crypto.getRandomValues(new Uint8Array(16));
  bytes[6] = (bytes[6] & 15) | 64; bytes[8] = (bytes[8] & 63) | 128;
  return Array.from(bytes, value => value.toString(16).padStart(2, "0")).join("");
}
export function parsed(value) { try { return JSON.parse(value); } catch { return value; } }
export const query = values => new URLSearchParams(Object.entries(values).filter(([, value]) => value !== null && value !== undefined)).toString();
export const caseUrl = (id, suffix = "") => `/api/v1/cases/${encodeURIComponent(id)}${suffix}`;
export const STAGES = [["reconnaissance", "Reconnaissance"], ["weaponization", "Weaponization"], ["delivery", "Delivery"], ["exploitation", "Exploitation"], ["installation", "Installation"], ["command_and_control", "Command and Control"], ["actions_on_objectives", "Actions on Objectives"]];
