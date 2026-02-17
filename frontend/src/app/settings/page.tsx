"use client";
import { useEffect, useState } from "react";
import AppShell from "../AppShell";
import { api, clearToken } from "@/lib/api";
import { Card } from "@/components/Card";
import { LogOut, Shield, Server, DollarSign, BarChart3, Loader2, Brain, Sparkles, Volume2, Bell, Smartphone, PartyPopper, Palette, Trophy, MessageSquare, RotateCcw } from "lucide-react";
import { useDopamineSettings } from "@/lib/dopamineSettings";
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
} from "recharts";
import { OWNER_LLM_PROVIDERS } from "@/lib/llmProviders";

const THINKING_LEVELS = [
  { id: "off", label: "Off", description: "No extra reasoning guidance." },
  { id: "minimal", label: "Minimal", description: "Very light reasoning, concise outputs." },
  { id: "low", label: "Low", description: "Short, focused reasoning." },
  { id: "medium", label: "Medium", description: "Balanced reasoning depth." },
  { id: "high", label: "High", description: "Deep, careful reasoning." },
  { id: "xhigh", label: "X-High", description: "Maximum reasoning budget." },
];

export default function SettingsPage() {
  return (
    <AppShell>
      <SettingsInner />
    </AppShell>
  );
}

function SettingsInner() {
  const [user, setUser] = useState<any>(null);
  const [health, setHealth] = useState<any>(null);

  // Owner LLM settings
  const [llmConfig, setLlmConfig] = useState<any>(null);
  const [llmLoading, setLlmLoading] = useState(false);
  const [llmSaving, setLlmSaving] = useState(false);
  const [llmProviderSaving, setLlmProviderSaving] = useState<Record<string, boolean>>({});
  const [llmInputs, setLlmInputs] = useState<Record<string, { auth_method: string; api_style: string; api_base: string; model: string; credential: string; enabled: boolean }>>({});
  const [llmDefaultProvider, setLlmDefaultProvider] = useState("");
  const [llmThinkingLevel, setLlmThinkingLevel] = useState("off");
  const [supervisorEnabled, setSupervisorEnabled] = useState(true);
  const [supervisorProvider, setSupervisorProvider] = useState("");
  const [supervisorLoaded, setSupervisorLoaded] = useState(false);
  const [supervisorSaving, setSupervisorSaving] = useState(false);

  // Usage state
  const [usage, setUsage] = useState<any>(null);
  const [exploitMode, setExploitMode] = useState<"disabled" | "explicit_only" | "autonomous">("explicit_only");
  const [exploitModeSaving, setExploitModeSaving] = useState(false);
  const [exploitModeLoaded, setExploitModeLoaded] = useState(false);
  const [jobDefaults, setJobDefaults] = useState<{ default_intensity: "low" | "medium" | "high"; default_timeout_seconds: number }>({
    default_intensity: "medium",
    default_timeout_seconds: 3600,
  });
  const [jobDefaultsSaving, setJobDefaultsSaving] = useState(false);
  const [jobDefaultsLoaded, setJobDefaultsLoaded] = useState(false);

  // Dopamine UX settings
  const { settings: dopamineSettings, updateSettings: updateDopamineSettings, reset: resetDopamine } = useDopamineSettings();

  async function loadLlmConfig() {
    setLlmLoading(true);
    try {
      const res = await api.get("/api/v1/settings/llm/config");
      setLlmConfig(res);
      setLlmDefaultProvider(res?.default_provider || "");
      setLlmThinkingLevel(res?.thinking_level || "off");

      const inputs: Record<string, { auth_method: string; api_style: string; api_base: string; model: string; credential: string; enabled: boolean }> = {};
      OWNER_LLM_PROVIDERS.forEach((provider) => {
        const status = res?.providers?.[provider.id] || {};
        inputs[provider.id] = {
          auth_method: status.auth_method || provider.authOptions[0]?.id || "api_key",
          api_style: status.api_style || provider.apiStyle,
          api_base: status.api_base ?? provider.defaultBase ?? "",
          model: status.model ?? provider.defaultModel ?? "",
          credential: "",
          enabled: status.enabled ?? false,
        };
      });
      setLlmInputs(inputs);
    } catch {
      setLlmConfig(null);
    } finally {
      setLlmLoading(false);
    }
  }

  function updateLlmInput(providerId: string, patch: Partial<{ auth_method: string; api_style: string; api_base: string; model: string; credential: string; enabled: boolean }>) {
    setLlmInputs((prev) => {
      const existing = prev[providerId] || {
        auth_method: "api_key",
        api_style: "openai",
        api_base: "",
        model: "",
        credential: "",
        enabled: false,
      };
      return {
        ...prev,
        [providerId]: { ...existing, ...patch },
      };
    });
  }

  async function saveLlmDefaults() {
    setLlmSaving(true);
    try {
      const res = await api.post("/api/v1/settings/llm/config", {
        default_provider: llmDefaultProvider || null,
        thinking_level: llmThinkingLevel,
      });
      setLlmConfig(res);
    } catch (e) {
      console.error(e);
    } finally {
      setLlmSaving(false);
    }
  }

  async function saveLlmProvider(providerId: string) {
    const input = llmInputs[providerId];
    if (!input) return;
    setLlmProviderSaving((prev) => ({ ...prev, [providerId]: true }));
    try {
      await api.post(`/api/v1/settings/llm/providers/${providerId}`, {
        auth_method: input.auth_method,
        api_style: input.api_style,
        api_base: input.api_base,
        model: input.model,
        credential: input.credential || undefined,
        enabled: input.enabled,
      });
      updateLlmInput(providerId, { credential: "", enabled: false });
      await loadLlmConfig();
    } catch (e) {
      console.error(e);
    } finally {
      setLlmProviderSaving((prev) => ({ ...prev, [providerId]: false }));
    }
  }

  async function clearLlmProvider(providerId: string) {
    setLlmProviderSaving((prev) => ({ ...prev, [providerId]: true }));
    try {
      await api.post(`/api/v1/settings/llm/providers/${providerId}`, { clear: true });
      updateLlmInput(providerId, { credential: "" });
      await loadLlmConfig();
    } catch (e) {
      console.error(e);
    } finally {
      setLlmProviderSaving((prev) => ({ ...prev, [providerId]: false }));
    }
  }

  useEffect(() => {
    api.get("/api/v1/auth/me").then(setUser).catch(() => {});
    api.get("/health/detailed").then(setHealth).catch(() => {});
    api.get("/api/v1/settings/usage").then(setUsage).catch(() => {});
    loadLlmConfig();
    api.get("/api/v1/settings/supervisor")
      .then((res) => {
        if (typeof res?.enabled === "boolean") {
          setSupervisorEnabled(res.enabled);
        }
        if (res?.provider) {
          setSupervisorProvider(res.provider);
        }
      })
      .finally(() => setSupervisorLoaded(true));
    api.get("/api/v1/settings/exploit-mode")
      .then((res) => {
        if (res?.exploit_mode) {
          setExploitMode(res.exploit_mode);
        }
      })
      .finally(() => setExploitModeLoaded(true));
    api.get("/api/v1/settings/job-defaults")
      .then((res) => {
        if (res?.default_intensity && res?.default_timeout_seconds) {
          setJobDefaults({
            default_intensity: res.default_intensity,
            default_timeout_seconds: res.default_timeout_seconds,
          });
        }
      })
      .finally(() => setJobDefaultsLoaded(true));
  }, []);

  function handleLogout() {
    clearToken();
    window.location.href = "/";
  }

  async function saveExploitMode() {
    setExploitModeSaving(true);
    try {
      await api.post("/api/v1/settings/exploit-mode", { exploit_mode: exploitMode });
    } catch (e) {
      console.error(e);
    } finally {
      setExploitModeSaving(false);
    }
  }

  async function saveJobDefaults() {
    setJobDefaultsSaving(true);
    try {
      await api.post("/api/v1/settings/job-defaults", {
        default_intensity: jobDefaults.default_intensity,
        default_timeout_seconds: jobDefaults.default_timeout_seconds,
      });
    } catch (e) {
      console.error(e);
    } finally {
      setJobDefaultsSaving(false);
    }
  }

  async function saveSupervisorSettings() {
    setSupervisorSaving(true);
    try {
      const res = await api.post("/api/v1/settings/supervisor", {
        enabled: supervisorEnabled,
        provider: supervisorProvider || null,
      });
      if (typeof res?.enabled === "boolean") {
        setSupervisorEnabled(res.enabled);
      }
      if (res?.provider !== undefined) {
        setSupervisorProvider(res.provider || "");
      }
    } catch (e) {
      console.error(e);
    } finally {
      setSupervisorSaving(false);
    }
  }

  const monthlyData = (usage?.monthly || []).map((m: any) => ({
    month: m.month.slice(5), // "01", "02", etc
    tokens: Math.round(m.tokens / 1000), // show in K
    cost: m.cost_usd,
    jobs: m.job_count,
  }));

  return (
    <div className="space-y-6 max-w-4xl">
        <h1 className="text-2xl font-bold">Settings</h1>

        {/* User Info */}
        <Card>
          <div className="flex items-center gap-4 mb-4">
            <div className="p-3 rounded-lg bg-indigo-500/20 text-indigo-400">
              <Shield className="w-6 h-6" />
            </div>
            <div>
              <h3 className="font-medium">{user?.email || "Loading..."}</h3>
              <p className="text-sm text-[var(--text-dim)]">Role: {user?.role || "—"}</p>
            </div>
          </div>
          <button
            onClick={handleLogout}
            className="flex items-center gap-2 px-4 py-2 rounded-lg bg-red-600/20 text-red-400 hover:bg-red-600/30 transition text-sm"
          >
            <LogOut className="w-4 h-4" /> Sign Out
          </button>
        </Card>

        {/* Default Exploit Mode */}
        <Card>
          <h3 className="text-lg font-medium mb-4 flex items-center gap-2">
            <Shield className="w-5 h-5 text-indigo-400" /> Default Exploit Mode
          </h3>
          <div className="flex items-center gap-2">
            <select
              className="flex-1 px-3 py-2 rounded-lg bg-[var(--surface2)] border border-[var(--border)] text-sm"
              value={exploitMode}
              onChange={(e) => setExploitMode(e.target.value as "disabled" | "explicit_only" | "autonomous")}
              disabled={!exploitModeLoaded}
            >
              <option value="explicit_only">Explicit Only (Recommended)</option>
              <option value="autonomous">Autonomous (Allow Exploit)</option>
              <option value="disabled">Disabled (No Exploit)</option>
            </select>
            <button
              onClick={saveExploitMode}
              disabled={!exploitModeLoaded || exploitModeSaving}
              className="px-4 py-2 rounded-lg bg-indigo-600 text-white text-sm hover:bg-indigo-500 disabled:opacity-50 transition flex items-center gap-1"
            >
              {exploitModeSaving && <Loader2 className="w-3 h-3 animate-spin" />}
              Save
            </button>
          </div>
          <p className="text-xs text-[var(--text-dim)] mt-2">
            This default is applied to new pentest jobs. External targets still require written authorization.
          </p>
        </Card>

        {/* Default Job Settings */}
        <Card>
          <h3 className="text-lg font-medium mb-4 flex items-center gap-2">
            <BarChart3 className="w-5 h-5 text-emerald-400" /> Default Job Settings
          </h3>
          <div className="grid grid-cols-2 gap-3">
            <div className="col-span-2 md:col-span-1">
              <label className="text-xs text-[var(--text-dim)]">Default Intensity</label>
              <select
                className="w-full px-3 py-2 rounded-lg bg-[var(--surface2)] border border-[var(--border)] text-sm"
                value={jobDefaults.default_intensity}
                onChange={(e) => setJobDefaults((prev) => ({ ...prev, default_intensity: e.target.value as "low" | "medium" | "high" }))}
                disabled={!jobDefaultsLoaded}
              >
                <option value="low">Low</option>
                <option value="medium">Medium</option>
                <option value="high">High</option>
              </select>
            </div>
            <div className="col-span-2 md:col-span-1">
              <label className="text-xs text-[var(--text-dim)]">Default Timeout (minutes)</label>
              <input
                type="number"
                min={1}
                max={240}
                step={1}
                className="w-full px-3 py-2 rounded-lg bg-[var(--surface2)] border border-[var(--border)] text-sm"
                value={Math.max(1, Math.round(jobDefaults.default_timeout_seconds / 60))}
                onChange={(e) => {
                  const minutes = Math.max(1, Math.min(240, Number(e.target.value)));
                  setJobDefaults((prev) => ({ ...prev, default_timeout_seconds: minutes * 60 }));
                }}
                disabled={!jobDefaultsLoaded}
              />
            </div>
          </div>
          <div className="flex justify-end mt-3">
            <button
              onClick={saveJobDefaults}
              disabled={!jobDefaultsLoaded || jobDefaultsSaving}
              className="px-4 py-2 rounded-lg bg-emerald-600 text-white text-sm hover:bg-emerald-500 disabled:opacity-50 transition flex items-center gap-1"
            >
              {jobDefaultsSaving && <Loader2 className="w-3 h-3 animate-spin" />}
              Save Defaults
            </button>
          </div>
          <p className="text-xs text-[var(--text-dim)] mt-2">
            These defaults apply to new jobs unless you override them in the pentest form.
          </p>
        </Card>

        {/* 🎰 Dopamine UX Settings */}
        <Card>
          <h3 className="text-lg font-medium mb-4 flex items-center gap-2">
            <Sparkles className="w-5 h-5 text-pink-400" /> Dopamine UX
          </h3>
          <p className="text-sm text-[var(--text-dim)] mb-4">
            Make pentesting feel like a game. Configure sounds, animations, and visual feedback when findings are discovered.
          </p>
          
          <div className="space-y-4">
            {/* Sound Settings */}
            <div className="flex items-center justify-between p-3 rounded-lg bg-[var(--surface2)] border border-[var(--border)]">
              <div className="flex items-center gap-3">
                <Volume2 className="w-5 h-5 text-blue-400" />
                <div>
                  <p className="text-sm font-medium">Sound Effects</p>
                  <p className="text-xs text-[var(--text-dim)]">Play chimes, fanfares, and combo sounds</p>
                </div>
              </div>
              <label className="relative inline-flex items-center cursor-pointer">
                <input
                  type="checkbox"
                  checked={dopamineSettings.soundEnabled}
                  onChange={(e) => updateDopamineSettings({ soundEnabled: e.target.checked })}
                  className="sr-only peer"
                />
                <div className="w-11 h-6 bg-gray-700 peer-focus:outline-none rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-indigo-600"></div>
              </label>
            </div>

            {/* Volume Slider */}
            {dopamineSettings.soundEnabled && (
              <div className="ml-8 p-3 rounded-lg bg-[var(--surface2)]/50 border border-[var(--border)]/50">
                <label className="text-xs text-[var(--text-dim)] block mb-2">Volume: {dopamineSettings.soundVolume}%</label>
                <input
                  type="range"
                  min="0"
                  max="100"
                  value={dopamineSettings.soundVolume}
                  onChange={(e) => updateDopamineSettings({ soundVolume: Number(e.target.value) })}
                  className="w-full h-2 bg-gray-700 rounded-lg appearance-none cursor-pointer accent-indigo-500"
                />
              </div>
            )}

            {/* Notifications */}
            <div className="flex items-center justify-between p-3 rounded-lg bg-[var(--surface2)] border border-[var(--border)]">
              <div className="flex items-center gap-3">
                <Bell className="w-5 h-5 text-yellow-400" />
                <div>
                  <p className="text-sm font-medium">Browser Notifications</p>
                  <p className="text-xs text-[var(--text-dim)]">Get notified when findings are discovered</p>
                </div>
              </div>
              <label className="relative inline-flex items-center cursor-pointer">
                <input
                  type="checkbox"
                  checked={dopamineSettings.notificationsEnabled}
                  onChange={(e) => updateDopamineSettings({ notificationsEnabled: e.target.checked })}
                  className="sr-only peer"
                />
                <div className="w-11 h-6 bg-gray-700 peer-focus:outline-none rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-indigo-600"></div>
              </label>
            </div>

            {/* Shake & Haptics */}
            <div className="flex items-center justify-between p-3 rounded-lg bg-[var(--surface2)] border border-[var(--border)]">
              <div className="flex items-center gap-3">
                <Smartphone className="w-5 h-5 text-green-400" />
                <div>
                  <p className="text-sm font-medium">Shake & Haptics</p>
                  <p className="text-xs text-[var(--text-dim)]">Screen shake + vibration on mobile</p>
                </div>
              </div>
              <label className="relative inline-flex items-center cursor-pointer">
                <input
                  type="checkbox"
                  checked={dopamineSettings.shakeEnabled}
                  onChange={(e) => updateDopamineSettings({ shakeEnabled: e.target.checked, hapticEnabled: e.target.checked })}
                  className="sr-only peer"
                />
                <div className="w-11 h-6 bg-gray-700 peer-focus:outline-none rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-indigo-600"></div>
              </label>
            </div>

            {/* Confetti */}
            <div className="flex items-center justify-between p-3 rounded-lg bg-[var(--surface2)] border border-[var(--border)]">
              <div className="flex items-center gap-3">
                <PartyPopper className="w-5 h-5 text-purple-400" />
                <div>
                  <p className="text-sm font-medium">Confetti Explosions</p>
                  <p className="text-xs text-[var(--text-dim)]">Celebrate critical findings with confetti</p>
                </div>
              </div>
              <label className="relative inline-flex items-center cursor-pointer">
                <input
                  type="checkbox"
                  checked={dopamineSettings.confettiEnabled}
                  onChange={(e) => updateDopamineSettings({ confettiEnabled: e.target.checked })}
                  className="sr-only peer"
                />
                <div className="w-11 h-6 bg-gray-700 peer-focus:outline-none rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-indigo-600"></div>
              </label>
            </div>

            {/* Background Pulse */}
            <div className="flex items-center justify-between p-3 rounded-lg bg-[var(--surface2)] border border-[var(--border)]">
              <div className="flex items-center gap-3">
                <Palette className="w-5 h-5 text-red-400" />
                <div>
                  <p className="text-sm font-medium">Background Pulse</p>
                  <p className="text-xs text-[var(--text-dim)]">Full-page glow effect on findings</p>
                </div>
              </div>
              <label className="relative inline-flex items-center cursor-pointer">
                <input
                  type="checkbox"
                  checked={dopamineSettings.backgroundPulseEnabled}
                  onChange={(e) => updateDopamineSettings({ backgroundPulseEnabled: e.target.checked })}
                  className="sr-only peer"
                />
                <div className="w-11 h-6 bg-gray-700 peer-focus:outline-none rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-indigo-600"></div>
              </label>
            </div>

            {/* Achievements */}
            <div className="flex items-center justify-between p-3 rounded-lg bg-[var(--surface2)] border border-[var(--border)]">
              <div className="flex items-center gap-3">
                <Trophy className="w-5 h-5 text-amber-400" />
                <div>
                  <p className="text-sm font-medium">Achievement Badges</p>
                  <p className="text-xs text-[var(--text-dim)]">Unlock badges for milestones</p>
                </div>
              </div>
              <label className="relative inline-flex items-center cursor-pointer">
                <input
                  type="checkbox"
                  checked={dopamineSettings.achievementsEnabled}
                  onChange={(e) => updateDopamineSettings({ achievementsEnabled: e.target.checked })}
                  className="sr-only peer"
                />
                <div className="w-11 h-6 bg-gray-700 peer-focus:outline-none rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-indigo-600"></div>
              </label>
            </div>

            {/* Encouragement Messages */}
            <div className="flex items-center justify-between p-3 rounded-lg bg-[var(--surface2)] border border-[var(--border)]">
              <div className="flex items-center gap-3">
                <MessageSquare className="w-5 h-5 text-cyan-400" />
                <div>
                  <p className="text-sm font-medium">Encouragement Messages</p>
                  <p className="text-xs text-[var(--text-dim)]">Fun rotating status messages</p>
                </div>
              </div>
              <label className="relative inline-flex items-center cursor-pointer">
                <input
                  type="checkbox"
                  checked={dopamineSettings.encouragementEnabled}
                  onChange={(e) => updateDopamineSettings({ encouragementEnabled: e.target.checked })}
                  className="sr-only peer"
                />
                <div className="w-11 h-6 bg-gray-700 peer-focus:outline-none rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-indigo-600"></div>
              </label>
            </div>

            {/* Reset Button */}
            <div className="flex justify-end pt-2">
              <button
                onClick={resetDopamine}
                className="flex items-center gap-2 px-4 py-2 rounded-lg bg-slate-700/50 text-slate-300 hover:bg-slate-700 transition text-sm"
              >
                <RotateCcw className="w-4 h-4" /> Reset to Defaults
              </button>
            </div>
          </div>
        </Card>

        {/* Supervisor Control */}
        <Card>
          <h3 className="text-lg font-medium mb-4 flex items-center gap-2">
            <Server className="w-5 h-5 text-emerald-400" /> Supervisor Control
          </h3>

          {!supervisorLoaded ? (
            <p className="text-sm text-[var(--text-dim)]">Loading supervisor settings...</p>
          ) : (
            <div className="space-y-3">
              <div className="flex items-center justify-between p-3 rounded-lg bg-[var(--surface2)] border border-[var(--border)]">
                <div className="flex items-center gap-3">
                  <Sparkles className="w-5 h-5 text-emerald-400" />
                  <div>
                    <p className="text-sm font-medium">Auto-Remediation Supervisor</p>
                    <p className="text-xs text-[var(--text-dim)]">
                      Watches agent logs and injects corrective guidance when anomalies appear.
                    </p>
                  </div>
                </div>
                <label className="relative inline-flex items-center cursor-pointer">
                  <input
                    type="checkbox"
                    checked={supervisorEnabled}
                    onChange={(e) => setSupervisorEnabled(e.target.checked)}
                    className="sr-only peer"
                  />
                  <div className="w-11 h-6 bg-gray-700 peer-focus:outline-none rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-emerald-600"></div>
                </label>
              </div>

              <div className="p-3 rounded-lg bg-[var(--surface2)] border border-[var(--border)]">
                <label className="text-xs text-[var(--text-dim)]">Supervisor LLM Provider</label>
                <select
                  className="w-full px-3 py-2 mt-1 rounded-lg bg-[var(--surface)] border border-[var(--border)] text-sm"
                  value={supervisorProvider}
                  onChange={(e) => setSupervisorProvider(e.target.value)}
                  disabled={!supervisorEnabled}
                >
                  <option value="">Use main default</option>
                  {OWNER_LLM_PROVIDERS.map((provider) => {
                    const enabled = llmInputs[provider.id]?.enabled;
                    return (
                      <option key={provider.id} value={provider.id} disabled={!enabled}>
                        {provider.label}{enabled ? "" : " (disabled)"}
                      </option>
                    );
                  })}
                </select>
                <p className="text-xs text-[var(--text-dim)] mt-1">
                  Choose which LLM supervises pentests. Same or different from the main pentest LLM.
                </p>
              </div>

              <div className="flex justify-end">
                <button
                  onClick={saveSupervisorSettings}
                  disabled={supervisorSaving}
                  className="px-4 py-2 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-sm font-medium disabled:opacity-50"
                >
                  {supervisorSaving ? "Saving..." : "Save Supervisor Settings"}
                </button>
              </div>
            </div>
          )}
        </Card>

        {/* Owner LLM Settings */}
        {(llmLoading || llmConfig) && (
          <Card>
            <h3 className="text-lg font-medium mb-4 flex items-center gap-2">
              <Brain className="w-5 h-5 text-cyan-400" /> Owner LLM Settings
            </h3>

            {llmLoading && !llmConfig ? (
              <p className="text-sm text-[var(--text-dim)]">Loading owner LLM settings...</p>
            ) : (
              <>
                <div className="grid grid-cols-2 gap-3">
                  <div className="col-span-2 md:col-span-1">
                    <label className="text-xs text-[var(--text-dim)]">Default Provider</label>
                    <select
                      className="w-full px-3 py-2 rounded-lg bg-[var(--surface2)] border border-[var(--border)] text-sm"
                      value={llmDefaultProvider}
                      onChange={(e) => setLlmDefaultProvider(e.target.value)}
                    >
                      <option value="">Use env default</option>
                      {OWNER_LLM_PROVIDERS.map((provider) => {
                        const enabled = llmInputs[provider.id]?.enabled;
                        return (
                          <option key={provider.id} value={provider.id} disabled={!enabled}>
                            {provider.label}{enabled ? "" : " (disabled)"}
                          </option>
                        );
                      })}
                    </select>
                  </div>
                  <div className="col-span-2 md:col-span-1">
                    <label className="text-xs text-[var(--text-dim)]">Thinking Level</label>
                    <select
                      className="w-full px-3 py-2 rounded-lg bg-[var(--surface2)] border border-[var(--border)] text-sm"
                      value={llmThinkingLevel}
                      onChange={(e) => setLlmThinkingLevel(e.target.value)}
                    >
                      {THINKING_LEVELS.map((level) => (
                        <option key={level.id} value={level.id}>
                          {level.label}
                        </option>
                      ))}
                    </select>
                  </div>
                </div>
                <div className="flex justify-end mt-3">
                  <button
                    onClick={saveLlmDefaults}
                    disabled={llmSaving}
                    className="px-4 py-2 rounded-lg bg-cyan-600 text-white text-sm hover:bg-cyan-500 disabled:opacity-50 transition flex items-center gap-1"
                  >
                    {llmSaving && <Loader2 className="w-3 h-3 animate-spin" />}
                    Save Defaults
                  </button>
                </div>
                <p className="text-xs text-[var(--text-dim)] mt-2">
                  These settings apply globally to all tenants. Z.AI supports binary thinking; any level above off maps to low.
                </p>

                <div className="mt-4 space-y-4">
                  {OWNER_LLM_PROVIDERS.map((provider) => {
                    const status = llmConfig?.providers?.[provider.id];
                    const input = llmInputs[provider.id] || {
                      auth_method: provider.authOptions[0]?.id || "api_key",
                      api_style: provider.apiStyle,
                      api_base: provider.defaultBase || "",
                      model: provider.defaultModel || "",
                      credential: "",
                      enabled: false,
                    };
                    const modelOptions = provider.models || [];
                    const hasModelOptions = modelOptions.length > 0;
                    const modelGroups = provider.modelGroups || [];
                    const hasModelGroups = modelGroups.length > 0;
                    const modelLabel = (model: string) => provider.modelLabels?.[model] || model;
                    const isKnownModel = hasModelOptions && modelOptions.includes(input.model);
                    const modelSelectValue = isKnownModel ? input.model : "__custom__";
                    const customModelValue = isKnownModel ? "" : input.model;

                    return (
                      <div key={provider.id} className="p-3 rounded-lg bg-[var(--surface2)] border border-[var(--border)]">
                        <div className="flex items-center justify-between">
                          <div>
                            <p className="font-medium">{provider.label}</p>
                            <p className="text-xs text-[var(--text-dim)]">{provider.id}</p>
                          </div>
                          <div className="flex items-center gap-2">
                            {status?.is_set ? (
                              <span className="text-xs font-mono px-2 py-0.5 rounded bg-emerald-600/20 text-emerald-400">
                                {status.masked_credential || "••••"}
                              </span>
                            ) : (
                              <span className="text-xs px-2 py-0.5 rounded bg-yellow-600/20 text-yellow-400">
                                Not set
                              </span>
                            )}
                            {llmDefaultProvider === provider.id && (
                              <span className="text-xs px-2 py-0.5 rounded bg-cyan-600/20 text-cyan-400">Default</span>
                            )}
                            <label className="flex items-center gap-1 text-[11px] text-[var(--text-dim)]">
                              <input
                                type="checkbox"
                                checked={input.enabled}
                                onChange={(e) => updateLlmInput(provider.id, { enabled: e.target.checked })}
                                className="rounded border-[var(--border)] bg-[var(--surface2)]"
                              />
                              Enabled
                            </label>
                          </div>
                        </div>

                        <div className="grid grid-cols-2 gap-3 mt-3">
                          <div className="col-span-2 md:col-span-1">
                            <label className="text-xs text-[var(--text-dim)]">Auth Method</label>
                            <select
                              className="w-full px-3 py-2 rounded-lg bg-[var(--surface2)] border border-[var(--border)] text-sm"
                              value={input.auth_method}
                              onChange={(e) => updateLlmInput(provider.id, { auth_method: e.target.value })}
                            >
                              {provider.authOptions.map((opt) => (
                                <option key={opt.id} value={opt.id}>
                                  {opt.label}
                                </option>
                              ))}
                            </select>
                          </div>
                          <div className="col-span-2 md:col-span-1">
                            <label className="text-xs text-[var(--text-dim)]">API Style</label>
                            <select
                              className="w-full px-3 py-2 rounded-lg bg-[var(--surface2)] border border-[var(--border)] text-sm"
                              value={input.api_style}
                              onChange={(e) => updateLlmInput(provider.id, { api_style: e.target.value })}
                            >
                              <option value="openai">OpenAI compatible</option>
                              <option value="anthropic">Anthropic messages</option>
                            </select>
                          </div>
                          <div className="col-span-2">
                            <label className="text-xs text-[var(--text-dim)]">API Base</label>
                            <input
                              type="text"
                              value={input.api_base}
                              onChange={(e) => updateLlmInput(provider.id, { api_base: e.target.value })}
                              placeholder="https://..."
                              className="w-full px-3 py-2 rounded-lg bg-[var(--surface2)] border border-[var(--border)] text-sm"
                            />
                          </div>
                          <div className="col-span-2">
                            <label className="text-xs text-[var(--text-dim)]">Model</label>
                            {hasModelOptions ? (
                              <>
                                <select
                                  className="w-full px-3 py-2 rounded-lg bg-[var(--surface2)] border border-[var(--border)] text-sm"
                                  value={modelSelectValue}
                                  onChange={(e) => {
                                    const next = e.target.value;
                                    if (next === "__custom__") {
                                      updateLlmInput(provider.id, { model: "" });
                                    } else {
                                      updateLlmInput(provider.id, { model: next });
                                    }
                                  }}
                                >
                                  {hasModelGroups
                                    ? modelGroups.map((group) => (
                                        <optgroup key={group.label} label={group.label}>
                                          {group.models.map((model) => (
                                            <option key={model} value={model}>
                                              {modelLabel(model)}
                                            </option>
                                          ))}
                                        </optgroup>
                                      ))
                                    : modelOptions.map((model) => (
                                        <option key={model} value={model}>
                                          {modelLabel(model)}
                                        </option>
                                      ))}
                                  <option value="__custom__">Custom...</option>
                                </select>
                                {modelSelectValue === "__custom__" && (
                                  <input
                                    type="text"
                                    value={customModelValue}
                                    onChange={(e) => updateLlmInput(provider.id, { model: e.target.value })}
                                    placeholder="provider/model"
                                    className="w-full mt-2 px-3 py-2 rounded-lg bg-[var(--surface2)] border border-[var(--border)] text-sm"
                                  />
                                )}
                              </>
                            ) : (
                              <input
                                type="text"
                                value={input.model}
                                onChange={(e) => updateLlmInput(provider.id, { model: e.target.value })}
                                placeholder="provider/model"
                                className="w-full px-3 py-2 rounded-lg bg-[var(--surface2)] border border-[var(--border)] text-sm"
                              />
                            )}
                          </div>
                          <div className="col-span-2">
                            <label className="text-xs text-[var(--text-dim)]">Credential</label>
                            <input
                              type="password"
                              value={input.credential}
                              onChange={(e) => updateLlmInput(provider.id, { credential: e.target.value })}
                              placeholder="Paste API key or token"
                              className="w-full px-3 py-2 rounded-lg bg-[var(--surface2)] border border-[var(--border)] text-sm"
                            />
                          </div>
                        </div>

                        <div className="flex justify-end gap-2 mt-3">
                          <button
                            onClick={() => saveLlmProvider(provider.id)}
                            disabled={llmProviderSaving[provider.id]}
                            className="px-4 py-2 rounded-lg bg-cyan-600 text-white text-sm hover:bg-cyan-500 disabled:opacity-50 transition flex items-center gap-1"
                          >
                            {llmProviderSaving[provider.id] && <Loader2 className="w-3 h-3 animate-spin" />}
                            Save
                          </button>
                          <button
                            onClick={() => clearLlmProvider(provider.id)}
                            disabled={llmProviderSaving[provider.id]}
                            className="px-4 py-2 rounded-lg bg-[var(--surface2)] border border-[var(--border)] text-sm hover:bg-white/5 transition"
                          >
                            Clear
                          </button>
                        </div>
                      </div>
                    );
                  })}
                </div>
              </>
            )}
          </Card>
        )}

        {/* Usage Dashboard */}
        <Card>
          <h3 className="text-lg font-medium mb-4 flex items-center gap-2">
            <DollarSign className="w-5 h-5 text-green-400" /> Usage & Billing
          </h3>

          {usage ? (
            <>
              {/* Stats row */}
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 mb-6">
                <div className="p-3 rounded-lg bg-[var(--surface2)]">
                  <p className="text-xs text-[var(--text-dim)]">Total Tokens</p>
                  <p className="text-xl font-bold">{(usage.total_tokens || 0).toLocaleString()}</p>
                </div>
                <div className="p-3 rounded-lg bg-[var(--surface2)]">
                  <p className="text-xs text-[var(--text-dim)]">Total Cost</p>
                  <p className="text-xl font-bold">${(usage.total_cost_usd || 0).toFixed(2)}</p>
                </div>
                <div className="p-3 rounded-lg bg-[var(--surface2)]">
                  <p className="text-xs text-[var(--text-dim)]">Total Jobs</p>
                  <p className="text-xl font-bold">{usage.total_jobs || 0}</p>
                </div>
                <div className="p-3 rounded-lg bg-[var(--surface2)]">
                  <p className="text-xs text-[var(--text-dim)]">Completed</p>
                  <p className="text-xl font-bold">{usage.completed_jobs || 0}</p>
                </div>
              </div>

              {/* Billing period */}
              <p className="text-xs text-[var(--text-dim)] mb-4">
                Billing period: {usage.billing_period_start?.slice(0, 10)} → {usage.billing_period_end?.slice(0, 10)}
              </p>

              {/* Monthly chart */}
              {monthlyData.length > 0 && (
                <div className="mb-6">
                  <h4 className="text-sm font-medium text-[var(--text-dim)] mb-2 flex items-center gap-1">
                    <BarChart3 className="w-4 h-4" /> Monthly Usage (tokens in K)
                  </h4>
                  <ResponsiveContainer width="100%" height={180}>
                    <BarChart data={monthlyData}>
                      <XAxis dataKey="month" stroke="#64748b" tick={{ fontSize: 11 }} />
                      <YAxis stroke="#64748b" tick={{ fontSize: 11 }} />
                      <Tooltip
                        contentStyle={{
                          background: "#1a1a2e",
                          border: "1px solid #2a2a3e",
                          borderRadius: 8,
                        }}
                        formatter={(value: any, name?: string) => {
                          if (name === "tokens") return [`${value}K tokens`, "Tokens"] as [string, string];
                          if (name === "cost") return [`$${value}`, "Cost"] as [string, string];
                          return [value, name || ""] as [string, string];
                        }}
                      />
                      <Bar dataKey="tokens" fill="#6366f1" radius={[4, 4, 0, 0]} />
                    </BarChart>
                  </ResponsiveContainer>
                </div>
              )}

              {/* Per-job breakdown */}
              {usage.per_job?.length > 0 && (
                <div>
                  <h4 className="text-sm font-medium text-[var(--text-dim)] mb-2">Cost Per Job</h4>
                  <div className="overflow-x-auto max-h-60 overflow-y-auto">
                    <table className="w-full text-sm">
                      <thead>
                        <tr className="text-left text-[var(--text-dim)] text-xs border-b border-white/10">
                          <th className="pb-2 pr-4">Job</th>
                          <th className="pb-2 pr-4">Phase</th>
                          <th className="pb-2 pr-4">Tokens</th>
                          <th className="pb-2 pr-4">Cost</th>
                          <th className="pb-2">Status</th>
                        </tr>
                      </thead>
                      <tbody>
                        {usage.per_job.map((j: any) => (
                          <tr key={j.job_id} className="border-b border-white/5">
                            <td className="py-1.5 pr-4 text-xs">{j.job_name}</td>
                            <td className="py-1.5 pr-4 text-xs text-[var(--text-dim)]">{j.phase}</td>
                            <td className="py-1.5 pr-4 text-xs font-mono">{(j.tokens_used || 0).toLocaleString()}</td>
                            <td className="py-1.5 pr-4 text-xs font-mono">${(j.cost_usd || 0).toFixed(4)}</td>
                            <td className="py-1.5 text-xs">{j.status}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>
              )}
            </>
          ) : (
            <p className="text-sm text-[var(--text-dim)]">Loading usage data...</p>
          )}
        </Card>

        {/* System Health */}
        <Card>
          <h3 className="text-lg font-medium mb-4 flex items-center gap-2">
            <Server className="w-5 h-5" /> System Health
          </h3>
          {health ? (
            <div className="space-y-2">
              <div className="flex justify-between">
                <span className="text-sm text-[var(--text-dim)]">API</span>
                <span className={`text-sm ${health.status === "healthy" ? "text-green-400" : "text-red-400"}`}>
                  {health.status}
                </span>
              </div>
              {health.dependencies &&
                Object.entries(health.dependencies).map(([k, v]) => (
                  <div key={k} className="flex justify-between">
                    <span className="text-sm text-[var(--text-dim)]">{k}</span>
                    <span className={`text-sm ${v === "healthy" ? "text-green-400" : "text-red-400"}`}>
                      {v as string}
                    </span>
                  </div>
                ))}
              <div className="flex justify-between">
                <span className="text-sm text-[var(--text-dim)]">Version</span>
                <span className="text-sm">{health.version}</span>
              </div>
            </div>
          ) : (
            <p className="text-sm text-[var(--text-dim)]">Loading...</p>
          )}
        </Card>
    </div>
  );
}
