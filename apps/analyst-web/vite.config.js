import {defineConfig, loadEnv} from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig(({mode}) => {
  const env = loadEnv(mode, process.cwd(), "");
  const upstream = new URL(process.env.ANALYST_API_UPSTREAM || env.ANALYST_API_UPSTREAM || "http://127.0.0.1:8001");
  if (!["http:", "https:"].includes(upstream.protocol) || upstream.username || upstream.password || upstream.search || upstream.hash || upstream.pathname !== "/") throw new Error("ANALYST_API_UPSTREAM must be an HTTP(S) origin without credentials or paths.");
  if (upstream.protocol === "http:" && !["localhost", "127.0.0.1", "[::1]"].includes(upstream.hostname)) throw new Error("Remote development API connections require verified HTTPS.");
  const proxy = {"/api/v1": {target: upstream.origin, changeOrigin: true, secure: true, timeout: 185000, proxyTimeout: 185000}};
  return {
    plugins: [react()],
    server: {host: "127.0.0.1", port: 5173, strictPort: true,
      proxy},
    preview: {host: "127.0.0.1", port: 4173, strictPort: true, proxy},
    build: {sourcemap: false},
  };
});
