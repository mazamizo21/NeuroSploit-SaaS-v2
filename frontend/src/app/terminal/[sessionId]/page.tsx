"use client";
import { useEffect, useRef, useState } from "react";
import { useParams } from "next/navigation";
import AppShell from "../../AppShell";
import { wsUrl } from "@/lib/api";

export default function TerminalPage() {
  return (
    <AppShell>
      <TerminalInner />
    </AppShell>
  );
}

function TerminalInner() {
  const { sessionId } = useParams();
  const termRef = useRef<HTMLDivElement>(null);
  const [status, setStatus] = useState("connecting");

  useEffect(() => {
    if (!termRef.current || !sessionId) return;

    let term: any;
    let ws: WebSocket | null = null;
    let handleResize: (() => void) | null = null;

    async function init() {
      const { Terminal } = await import("@xterm/xterm");
      const { FitAddon } = await import("@xterm/addon-fit");
      const { WebLinksAddon } = await import("@xterm/addon-web-links");
      term = new Terminal({
        cursorBlink: true,
        theme: {
          background: "#0a0a0f",
          foreground: "#e2e8f0",
          cursor: "#6366f1",
          selectionBackground: "#6366f1",
        },
        fontFamily: "'JetBrains Mono', 'Fira Code', monospace",
        fontSize: 13,
      });

      const fitAddon = new FitAddon();
      term.loadAddon(fitAddon);
      term.loadAddon(new WebLinksAddon());
      term.open(termRef.current!);
      fitAddon.fit();

      handleResize = () => fitAddon.fit();
      window.addEventListener("resize", handleResize);

      // Connect WebSocket
      ws = new WebSocket(wsUrl(`/api/v1/terminal/ws/terminal/${sessionId}`));
      ws.binaryType = "arraybuffer";

      ws.onopen = () => {
        setStatus("connected");
        term.writeln("\\x1b[32mConnected to Kali container\\x1b[0m\\r\\n");
      };

      ws.onmessage = (e) => {
        if (e.data instanceof ArrayBuffer) {
          term.write(new Uint8Array(e.data));
        } else {
          term.write(e.data);
        }
      };

      ws.onclose = () => {
        setStatus("disconnected");
        term.writeln("\\r\\n\\x1b[31mDisconnected\\x1b[0m");
      };

      ws.onerror = () => {
        setStatus("error");
      };

      term.onData((data: string) => {
        if (ws && ws.readyState === WebSocket.OPEN) {
          ws.send(data);
        }
      });
    }

    init();

    return () => {
      if (handleResize) window.removeEventListener("resize", handleResize);
      ws?.close();
      term?.dispose();
    };
  }, [sessionId]);

  return (
    <div className="space-y-4">
        <div className="flex items-center justify-between">
          <h1 className="text-xl font-bold">Terminal Session</h1>
          <span
            className={`text-sm font-medium ${
              status === "connected"
                ? "text-green-400"
                : status === "connecting"
                ? "text-yellow-400"
                : "text-red-400"
            }`}
          >
            ● {status}
          </span>
        </div>
        <div
          ref={termRef}
          className="rounded-xl border border-[var(--border)] overflow-hidden"
          style={{ height: "calc(100vh - 160px)" }}
        />
    </div>
  );
}
