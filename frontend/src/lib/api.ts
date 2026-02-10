function getBaseUrl() {
  if (typeof window === "undefined") return "http://localhost:8000";
  // In the browser, always derive from current hostname so remote access
  // (e.g. via LAN/Tailscale IP) works without rebuilding the frontend.
  const host = window.location.hostname;
  const proto = window.location.protocol;
  return `${proto}//${host}:8000`;
}
function getWsUrl() {
  if (typeof window === "undefined") return "ws://localhost:8000";
  const host = window.location.hostname;
  const wsproto = window.location.protocol === "https:" ? "wss:" : "ws:";
  return `${wsproto}//${host}:8000`;
}
const API_URL = getBaseUrl();
const WS_URL = getWsUrl();

let _token: string | null = null;

export function setToken(t: string) {
  _token = t;
  if (typeof window !== "undefined") {
    localStorage.setItem("token", t);
    window.dispatchEvent(new Event("auth-changed"));
  }
}
export function getToken(): string | null {
  if (_token) return _token;
  if (typeof window !== "undefined") {
    _token = localStorage.getItem("token");
  }
  return _token;
}
export function clearToken() {
  _token = null;
  if (typeof window !== "undefined") {
    localStorage.removeItem("token");
    window.dispatchEvent(new Event("auth-changed"));
  }
}

async function apiFetch(path: string, opts: RequestInit = {}) {
  const token = getToken();
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    ...(opts.headers as Record<string, string>),
  };
  if (token) headers["Authorization"] = `Bearer ${token}`;

  const res = await fetch(`${API_URL}${path}`, { ...opts, headers });
  if (res.status === 401) {
    clearToken();
    throw new Error("Unauthorized");
  }
  if (!res.ok) {
    const text = await res.text().catch(() => "");
    throw new Error(`API error ${res.status}: ${text}`);
  }
  return res;
}

export const api = {
  get: (path: string) => apiFetch(path).then((r) => r.json()),
  post: (path: string, body: unknown) =>
    apiFetch(path, { method: "POST", body: JSON.stringify(body) }).then((r) => r.json()),
  patch: (path: string, body: unknown) =>
    apiFetch(path, { method: "PATCH", body: JSON.stringify(body) }).then((r) => r.json()),
  delete: (path: string) => apiFetch(path, { method: "DELETE" }).then((r) => r.json()),
  getBlob: (path: string) => apiFetch(path).then((r) => r.blob()),
};

export function wsUrl(path: string) {
  const token = getToken();
  return `${WS_URL}${path}${token ? `?token=${token}` : ""}`;
}

export { API_URL, WS_URL };
