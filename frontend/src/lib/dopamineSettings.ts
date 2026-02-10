// 🎰 Dopamine UX Settings - Persisted to localStorage

export interface DopamineSettings {
  soundEnabled: boolean;
  notificationsEnabled: boolean;
  shakeEnabled: boolean;
  hapticEnabled: boolean;
  confettiEnabled: boolean;
  backgroundPulseEnabled: boolean;
  achievementsEnabled: boolean;
  encouragementEnabled: boolean;
  soundVolume: number; // 0-100
}

const DEFAULT_SETTINGS: DopamineSettings = {
  soundEnabled: true,
  notificationsEnabled: true,
  shakeEnabled: true,
  hapticEnabled: true,
  confettiEnabled: true,
  backgroundPulseEnabled: true,
  achievementsEnabled: true,
  encouragementEnabled: true,
  soundVolume: 50,
};

const STORAGE_KEY = "tazosploit_dopamine_settings";

export function getDopamineSettings(): DopamineSettings {
  if (typeof window === "undefined") return DEFAULT_SETTINGS;
  
  try {
    const stored = localStorage.getItem(STORAGE_KEY);
    if (stored) {
      return { ...DEFAULT_SETTINGS, ...JSON.parse(stored) };
    }
  } catch (e) {
    console.error("Failed to load dopamine settings:", e);
  }
  return DEFAULT_SETTINGS;
}

export function saveDopamineSettings(settings: Partial<DopamineSettings>): DopamineSettings {
  const current = getDopamineSettings();
  const updated = { ...current, ...settings };
  
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(updated));
  } catch (e) {
    console.error("Failed to save dopamine settings:", e);
  }
  
  // Dispatch event so other components can react
  if (typeof window !== "undefined") {
    window.dispatchEvent(new CustomEvent("dopamine-settings-changed", { detail: updated }));
  }
  
  return updated;
}

export function resetDopamineSettings(): DopamineSettings {
  try {
    localStorage.removeItem(STORAGE_KEY);
  } catch (e) {
    console.error("Failed to reset dopamine settings:", e);
  }
  
  if (typeof window !== "undefined") {
    window.dispatchEvent(new CustomEvent("dopamine-settings-changed", { detail: DEFAULT_SETTINGS }));
  }
  
  return DEFAULT_SETTINGS;
}

// Hook for React components
import { useState, useEffect } from "react";

export function useDopamineSettings() {
  const [settings, setSettings] = useState<DopamineSettings>(DEFAULT_SETTINGS);
  
  useEffect(() => {
    // Load initial settings
    setSettings(getDopamineSettings());
    
    // Listen for changes from other tabs/components
    const handleChange = (e: CustomEvent<DopamineSettings>) => {
      setSettings(e.detail);
    };
    
    window.addEventListener("dopamine-settings-changed", handleChange as EventListener);
    return () => window.removeEventListener("dopamine-settings-changed", handleChange as EventListener);
  }, []);
  
  const updateSettings = (patch: Partial<DopamineSettings>) => {
    const updated = saveDopamineSettings(patch);
    setSettings(updated);
  };
  
  const reset = () => {
    const defaults = resetDopamineSettings();
    setSettings(defaults);
  };
  
  return { settings, updateSettings, reset };
}
