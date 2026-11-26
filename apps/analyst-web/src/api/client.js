/* Same-origin authenticated transport. Credentials are never persisted or placed in URLs. */
export class ApiError extends Error {
  constructor(message, status = 0, uncertain = false) { super(message); this.status = status; this.uncertain = uncertain; }
}
export class ApiClient {
  #token = "";
  #generation = 0;
  #requests = new Set();
  onUnauthorized = () => {};
  clear() {
    this.#generation += 1;
    this.#token = "";
    for (const controller of this.#requests) controller.abort();
    this.#requests.clear();
  }
  async connect(token) {
    this.clear();
    if (!/^[\x21-\x7e]{32,512}$/.test(token)) throw new ApiError("Enter your assigned analyst access token.", 400);
    this.#token = token;
    try { return await this.request("/api/v1/me"); }
    catch (error) { this.clear(); throw error; }
  }
  async request(path, {method = "GET", body, signal, timeout = method === "GET" ? 30000 : 180000} = {}) {
    if (!path.startsWith("/api/v1/") || path.startsWith("//") || !this.#token) throw new ApiError("Connect to the workspace first.", 401);
    const url = new URL(path, location.origin);
    if (url.origin !== location.origin || url.hash) throw new ApiError("Only this workspace's API can be contacted.", 400);
    const generation = this.#generation, controller = new AbortController();
    const cancel = () => controller.abort();
    if (signal?.aborted) controller.abort();
    signal?.addEventListener("abort", cancel, {once: true});
    this.#requests.add(controller);
    const timer = setTimeout(() => controller.abort(), timeout);
    const changed = method !== "GET";
    let receivedStatus = 0;
    try {
      const response = await fetch(url, {method, headers: {Authorization: `Bearer ${this.#token}`, Accept: "application/json", ...(body === undefined ? {} : {"Content-Type": "application/json"})},
        body: body === undefined ? undefined : JSON.stringify(body), credentials: "omit", cache: "no-store", redirect: "error", signal: controller.signal});
      receivedStatus = response.status;
      if (generation !== this.#generation || signal?.aborted) throw new DOMException("Request cancelled", "AbortError");
      if (response.status === 401) {
        this.clear(); this.onUnauthorized();
        throw new ApiError("Your credential expired or was revoked. Connect again.", 401);
      }
      if (response.status === 413) throw new ApiError("Request exceeds the configured size limit.",413);
      if (!response.headers.get("content-type")?.toLowerCase().startsWith("application/json")) throw new ApiError("The server returned an unexpected response. Refresh saved state.", response.status, changed);
      const reader = response.body.getReader(), decoder = new TextDecoder(), parts = [];
      let size = 0;
      while (true) {
        const {value, done} = await reader.read();
        if (done) break;
        size += value.byteLength;
        if (size > 20 * 1024 * 1024) { await reader.cancel(); throw new ApiError("The response exceeds the console's display limit.", response.status, changed); }
        parts.push(decoder.decode(value, {stream: true}));
      }
      parts.push(decoder.decode());
      if (generation !== this.#generation || signal?.aborted) throw new DOMException("Request cancelled", "AbortError");
      const data = JSON.parse(parts.join(""));
      if (!response.ok) throw new ApiError(typeof data.detail === "string" ? data.detail : `Request failed (${response.status}).`, response.status, changed && response.status >= 500);
      return data;
    } catch (error) {
      if (generation !== this.#generation || signal?.aborted) throw new DOMException("Request cancelled", "AbortError");
      if (error instanceof ApiError) throw error;
      throw new ApiError(changed ? "No confirmed response was received. Read the saved state before submitting another operation." : "The workspace request could not complete. Check the server and refresh.", receivedStatus, changed);
    } finally {
      clearTimeout(timer); this.#requests.delete(controller); signal?.removeEventListener("abort",cancel);
    }
  }
}
