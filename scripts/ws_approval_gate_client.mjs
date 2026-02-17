#!/usr/bin/env node
/**
 * ws_approval_gate_client.mjs
 *
 * Minimal WebSocket client to validate Approval Gate flow end-to-end:
 * - Connects to Control Plane WS chat endpoint
 * - Waits for `approval_request`
 * - Sends `approval` decision
 * - Exits 0 on `approval_ack`
 *
 * Env:
 * - WS_URL (required)
 * - DECISION (approve|modify|abort) [default: approve]
 * - MODIFICATION (optional; only used when decision=modify)
 * - TIMEOUT_MS [default: 60000]
 */

function redactWsUrl(raw) {
  try {
    const u = new URL(String(raw || ""));
    if (u.searchParams.has("token")) u.searchParams.set("token", "<redacted>");
    return u.toString();
  } catch {
    return "<invalid_ws_url>";
  }
}

function safeJsonParse(text) {
  try {
    return JSON.parse(String(text || ""));
  } catch {
    return null;
  }
}

const wsUrl = process.env.WS_URL;
if (!wsUrl) {
  console.error("[ws_approval_gate_client] WS_URL env var is required");
  process.exit(2);
}

const decision = String(process.env.DECISION || "approve").trim().toLowerCase();
const modification = String(process.env.MODIFICATION || "").trim();
const timeoutMs = Number(process.env.TIMEOUT_MS || "60000");

if (!Number.isFinite(timeoutMs) || timeoutMs < 1000) {
  console.error("[ws_approval_gate_client] TIMEOUT_MS must be a number >= 1000");
  process.exit(2);
}

if (!["approve", "modify", "abort"].includes(decision)) {
  console.error(`[ws_approval_gate_client] invalid DECISION=${decision}`);
  process.exit(2);
}

let sentDecision = false;
let done = false;

const timer = setTimeout(() => {
  if (done) return;
  console.error(`[ws_approval_gate_client] TIMEOUT after ${timeoutMs}ms (no approval_ack)`);
  process.exit(1);
}, timeoutMs);

actionLog("start", { url: redactWsUrl(wsUrl), decision });

function actionLog(event, payload) {
  const line = {
    ts: new Date().toISOString(),
    event,
    ...(payload ? { payload } : {}),
  };
  console.log(JSON.stringify(line));
}

function send(ws, type, payload) {
  const msg = { type, payload: payload || {} };
  ws.send(JSON.stringify(msg));
  actionLog("ws_send", { type });
}

const ws = new WebSocket(wsUrl);

ws.onopen = () => {
  actionLog("ws_open", {});
};

ws.onmessage = (ev) => {
  const obj = safeJsonParse(ev.data);
  if (!obj || typeof obj.type !== "string") return;

  const t = String(obj.type || "").toLowerCase();
  actionLog("ws_recv", { type: t });

  if (t === "error") {
    console.error("[ws_approval_gate_client] server_error", JSON.stringify(obj));
    process.exit(1);
  }

  if (t === "approval_request" && !sentDecision) {
    sentDecision = true;
    const payload = { decision };
    if (decision === "modify" && modification) payload.modification = modification;
    send(ws, "approval", payload);
    return;
  }

  if (t === "approval_ack") {
    done = true;
    clearTimeout(timer);
    actionLog("success", { ack: obj.payload || {} });
    try {
      ws.close();
    } catch {
      // ignore
    }
    process.exit(0);
  }
};

ws.onerror = () => {
  // onerror doesn't give much detail; onclose will typically follow.
  actionLog("ws_error", {});
};

ws.onclose = (ev) => {
  actionLog("ws_close", { code: ev.code, reason: ev.reason });
  if (!done) {
    clearTimeout(timer);
    process.exit(1);
  }
};
