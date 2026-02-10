"use client";
import { useEffect, useState } from "react";
import AppShell from "../AppShell";
import { api } from "@/lib/api";
import { Card } from "@/components/Card";
import { formatDate } from "@/lib/utils";
import { Plus, RefreshCw, Wifi, WifiOff, Copy, Trash2, Network } from "lucide-react";

interface Agent {
  id: string;
  name: string;
  status: string;
  wg_assigned_ip: string | null;
  last_heartbeat: string | null;
  client_info: Record<string, string> | null;
  created_at: string;
}

export default function AgentsPage() {
  return (
    <AppShell>
      <AgentsInner />
    </AppShell>
  );
}

function AgentsInner() {
  const [agents, setAgents] = useState<Agent[]>([]);
  const [loading, setLoading] = useState(true);
  const [showCreate, setShowCreate] = useState(false);
  const [newToken, setNewToken] = useState<{ token: string; install_command: string } | null>(null);

  function loadAgents() {
    setLoading(true);
    api
      .get("/api/v1/agents")
      .then(setAgents)
      .catch(() => {})
      .finally(() => setLoading(false));
  }

  useEffect(() => {
    loadAgents();
  }, []);

  return (
    <div className="space-y-6">
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-2xl font-bold">Tunnel Agents</h1>
            <p className="text-sm text-[var(--text-dim)] mt-1">
              WireGuard tunnel agents for internal network access
            </p>
          </div>
          <div className="flex gap-2">
            <button
              onClick={loadAgents}
              className="px-3 py-2 rounded-lg bg-[var(--surface2)] border border-[var(--border)] hover:bg-white/5 transition"
            >
              <RefreshCw className="w-4 h-4" />
            </button>
            <button
              onClick={() => {
                setShowCreate(true);
                setNewToken(null);
              }}
              className="flex items-center gap-2 px-4 py-2 rounded-lg bg-indigo-600 hover:bg-indigo-500 transition text-sm font-medium"
            >
              <Plus className="w-4 h-4" /> Add Agent
            </button>
          </div>
        </div>

        {showCreate && (
          <CreateAgentForm
            onCreated={(token) => {
              setNewToken(token);
              loadAgents();
            }}
            onCancel={() => {
              setShowCreate(false);
              setNewToken(null);
            }}
            newToken={newToken}
          />
        )}

        {loading ? (
          <p className="text-[var(--text-dim)]">Loading...</p>
        ) : agents.length === 0 ? (
          <Card className="text-center py-12">
            <Network className="w-12 h-12 mx-auto mb-4 text-[var(--text-dim)]" />
            <p className="text-lg">No agents configured</p>
            <p className="text-sm text-[var(--text-dim)]">
              Add an agent to create a WireGuard tunnel for internal network pentesting
            </p>
          </Card>
        ) : (
          <div className="space-y-3">
            {agents.map((agent) => (
              <AgentCard key={agent.id} agent={agent} onDelete={loadAgents} />
            ))}
          </div>
        )}

        {/* Info section */}
        <Card className="bg-indigo-500/5 border-indigo-500/20">
          <h3 className="text-sm font-medium text-indigo-400 mb-2">How Tunnel Agents Work</h3>
          <ol className="text-sm text-[var(--text-dim)] space-y-1 list-decimal list-inside">
            <li>Click &quot;Add Agent&quot; to generate a one-time connection token</li>
            <li>Run the agent binary on the target network with the token</li>
            <li>A WireGuard tunnel is established back to TazoSploit</li>
            <li>Create a pentest targeting internal IPs — traffic routes through the tunnel</li>
            <li>The agent is just a tunnel — no tools or commands run locally</li>
          </ol>
        </Card>
    </div>
  );
}

function AgentCard({ agent, onDelete }: { agent: Agent; onDelete: () => void }) {
  const [deleting, setDeleting] = useState(false);
  const [error, setError] = useState("");

  async function handleDelete(e: React.MouseEvent) {
    e.preventDefault();
    e.stopPropagation();
    if (!confirm(`Delete agent "${agent.name}"? This will disconnect the tunnel.`)) return;
    setDeleting(true);
    setError("");
    try {
      await api.delete(`/api/v1/agents/${agent.id}`);
      onDelete();
    } catch (err: any) {
      console.error("Delete failed:", err);
      setError(err?.message || "Failed to delete agent");
    } finally {
      setDeleting(false);
    }
  }

  const statusIcon =
    agent.status === "connected" ? (
      <Wifi className="w-4 h-4 text-green-400" />
    ) : (
      <WifiOff className="w-4 h-4 text-[var(--text-dim)]" />
    );

  const statusColor =
    agent.status === "connected"
      ? "text-green-400"
      : agent.status === "pending"
      ? "text-amber-400"
      : "text-[var(--text-dim)]";

  return (
    <Card>
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          {statusIcon}
          <div>
            <h3 className="font-medium">{agent.name}</h3>
            <p className="text-sm text-[var(--text-dim)]">
              {agent.wg_assigned_ip && <span>IP: {agent.wg_assigned_ip} · </span>}
              {agent.client_info?.os && <span>{agent.client_info.os}/{agent.client_info.arch} · </span>}
              {agent.client_info?.hostname && <span>{agent.client_info.hostname} · </span>}
              Created {formatDate(agent.created_at)}
            </p>
          </div>
        </div>
        <div className="flex items-center gap-4">
          <div className="text-right">
            <span className={`text-sm font-medium ${statusColor}`}>● {agent.status}</span>
            {agent.last_heartbeat && (
              <p className="text-xs text-[var(--text-dim)]">
                Last seen: {formatDate(agent.last_heartbeat)}
              </p>
            )}
          </div>
          <button
            onClick={handleDelete}
            disabled={deleting}
            className="p-2 rounded-lg hover:bg-red-500/10 text-[var(--text-dim)] hover:text-red-400 transition disabled:opacity-50"
            title={`Delete ${agent.name}`}
          >
            {deleting ? (
              <RefreshCw className="w-4 h-4 animate-spin" />
            ) : (
              <Trash2 className="w-4 h-4" />
            )}
          </button>
        </div>
      </div>
      {error && (
        <p className="text-xs text-red-400 mt-2">{error}</p>
      )}
    </Card>
  );
}

function CreateAgentForm({
  onCreated,
  onCancel,
  newToken,
}: {
  onCreated: (token: { token: string; install_command: string }) => void;
  onCancel: () => void;
  newToken: { token: string; install_command: string } | null;
}) {
  const [name, setName] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [copied, setCopied] = useState(false);

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setLoading(true);
    setError("");
    try {
      const result = await api.post("/api/v1/agents", { name });
      onCreated(result);
    } catch (err: any) {
      setError(err.message || "Failed to create agent");
    } finally {
      setLoading(false);
    }
  }

  function copyToClipboard(text: string) {
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  }

  const inputCls =
    "w-full px-3 py-2 rounded-lg bg-[var(--surface2)] border border-[var(--border)] text-white text-sm";

  if (newToken) {
    return (
      <Card className="border-green-500/30">
        <h3 className="text-lg font-medium mb-2 text-green-400">✅ Agent Token Created</h3>
        <p className="text-sm text-amber-400 mb-4">
          ⚠️ Copy the token now — it will only be shown once!
        </p>

        <div className="space-y-3">
          <div>
            <label className="text-xs text-[var(--text-dim)]">Token</label>
            <div className="flex gap-2">
              <code className="flex-1 px-3 py-2 rounded-lg bg-black/50 border border-[var(--border)] text-green-400 text-sm font-mono break-all">
                {newToken.token}
              </code>
              <button
                onClick={() => copyToClipboard(newToken.token)}
                className="px-3 py-2 rounded-lg bg-[var(--surface2)] border border-[var(--border)] hover:bg-white/5"
              >
                <Copy className="w-4 h-4" />
              </button>
            </div>
          </div>

          <div>
            <label className="text-xs text-[var(--text-dim)]">Install Command</label>
            <div className="flex gap-2">
              <code className="flex-1 px-3 py-2 rounded-lg bg-black/50 border border-[var(--border)] text-cyan-400 text-sm font-mono break-all">
                {newToken.install_command}
              </code>
              <button
                onClick={() => copyToClipboard(newToken.install_command)}
                className="px-3 py-2 rounded-lg bg-[var(--surface2)] border border-[var(--border)] hover:bg-white/5"
              >
                <Copy className="w-4 h-4" />
              </button>
            </div>
          </div>
        </div>

        {copied && <p className="text-green-400 text-sm mt-2">✅ Copied to clipboard</p>}

        <div className="flex justify-end mt-4">
          <button
            onClick={onCancel}
            className="px-4 py-2 rounded-lg bg-[var(--surface2)] text-sm"
          >
            Done
          </button>
        </div>
      </Card>
    );
  }

  return (
    <Card>
      <h3 className="text-lg font-medium mb-4">Add New Agent</h3>
      {error && <p className="text-red-400 text-sm mb-2">{error}</p>}
      <form onSubmit={handleSubmit} className="space-y-4">
        <div>
          <label className="text-xs text-[var(--text-dim)]">Agent Name</label>
          <input
            className={inputCls}
            value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder="e.g. Client Office Network, Production DMZ"
            required
          />
        </div>
        <div className="flex gap-2 justify-end">
          <button
            type="button"
            onClick={onCancel}
            className="px-4 py-2 rounded-lg bg-[var(--surface2)] text-sm"
          >
            Cancel
          </button>
          <button
            type="submit"
            disabled={loading}
            className="px-4 py-2 rounded-lg bg-indigo-600 hover:bg-indigo-500 text-sm font-medium disabled:opacity-50"
          >
            {loading ? "Creating..." : "Generate Token"}
          </button>
        </div>
      </form>
    </Card>
  );
}
