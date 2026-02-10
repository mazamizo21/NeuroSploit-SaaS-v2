"use client";
import { useEffect, useState, useRef, useCallback } from "react";
import { Shield, Key, Database, Zap, Trophy, Flame, Star, Target, Skull } from "lucide-react";
import { useDopamineSettings } from "@/lib/dopamineSettings";

// 🎵 Sound System - Candy Crush style
class SoundEngine {
  private ctx: AudioContext | null = null;
  private enabled = true;
  private volume = 0.5;

  private getContext() {
    if (!this.ctx) {
      this.ctx = new (window.AudioContext || (window as any).webkitAudioContext)();
    }
    return this.ctx;
  }

  setEnabled(enabled: boolean) {
    this.enabled = enabled;
  }
  
  setVolume(vol: number) {
    this.volume = Math.max(0, Math.min(1, vol));
  }

  toggle() {
    this.enabled = !this.enabled;
    return this.enabled;
  }
  
  isEnabled() {
    return this.enabled;
  }

  // Rising chime for normal findings
  playFind() {
    if (!this.enabled) return;
    const ctx = this.getContext();
    const osc = ctx.createOscillator();
    const gain = ctx.createGain();
    osc.connect(gain);
    gain.connect(ctx.destination);
    osc.type = "sine";
    
    // Pleasant rising arpeggio
    osc.frequency.setValueAtTime(523, ctx.currentTime); // C5
    osc.frequency.setValueAtTime(659, ctx.currentTime + 0.08); // E5
    osc.frequency.setValueAtTime(784, ctx.currentTime + 0.16); // G5
    
    gain.gain.setValueAtTime(0.2 * this.volume, ctx.currentTime);
    gain.gain.exponentialRampToValueAtTime(0.01, ctx.currentTime + 0.3);
    
    osc.start(ctx.currentTime);
    osc.stop(ctx.currentTime + 0.3);
  }

  // Dramatic chord for high severity
  playHighSeverity() {
    if (!this.enabled) return;
    const ctx = this.getContext();
    
    // Play a power chord
    [440, 554, 659].forEach((freq) => {
      const osc = ctx.createOscillator();
      const gain = ctx.createGain();
      osc.connect(gain);
      gain.connect(ctx.destination);
      osc.type = "sawtooth";
      osc.frequency.setValueAtTime(freq, ctx.currentTime);
      gain.gain.setValueAtTime(0.15, ctx.currentTime);
      gain.gain.exponentialRampToValueAtTime(0.01, ctx.currentTime + 0.5);
      osc.start(ctx.currentTime);
      osc.stop(ctx.currentTime + 0.5);
    });
  }

  // Epic fanfare for critical findings
  playCritical() {
    if (!this.enabled) return;
    const ctx = this.getContext();
    
    // Dramatic ascending fanfare
    const notes = [523, 659, 784, 1046]; // C5 E5 G5 C6
    notes.forEach((freq, i) => {
      const osc = ctx.createOscillator();
      const gain = ctx.createGain();
      osc.connect(gain);
      gain.connect(ctx.destination);
      osc.type = i === 3 ? "square" : "sawtooth";
      osc.frequency.setValueAtTime(freq, ctx.currentTime + i * 0.1);
      gain.gain.setValueAtTime(0, ctx.currentTime + i * 0.1);
      gain.gain.linearRampToValueAtTime(0.2, ctx.currentTime + i * 0.1 + 0.05);
      gain.gain.exponentialRampToValueAtTime(0.01, ctx.currentTime + i * 0.1 + 0.4);
      osc.start(ctx.currentTime + i * 0.1);
      osc.stop(ctx.currentTime + i * 0.1 + 0.4);
    });
  }

  // Combo sound - quick ascending blips
  playCombo(count: number) {
    if (!this.enabled) return;
    const ctx = this.getContext();
    const baseFreq = 400 + Math.min(count, 10) * 50;
    
    for (let i = 0; i < Math.min(count, 5); i++) {
      const osc = ctx.createOscillator();
      const gain = ctx.createGain();
      osc.connect(gain);
      gain.connect(ctx.destination);
      osc.type = "sine";
      osc.frequency.setValueAtTime(baseFreq + i * 100, ctx.currentTime + i * 0.05);
      gain.gain.setValueAtTime(0.15, ctx.currentTime + i * 0.05);
      gain.gain.exponentialRampToValueAtTime(0.01, ctx.currentTime + i * 0.05 + 0.1);
      osc.start(ctx.currentTime + i * 0.05);
      osc.stop(ctx.currentTime + i * 0.05 + 0.1);
    }
  }

  // Achievement unlocked!
  playAchievement() {
    if (!this.enabled) return;
    const ctx = this.getContext();
    
    // Magical sparkle + fanfare
    const sparkles = [1318, 1567, 2093, 2637]; // High harmonics
    sparkles.forEach((freq, i) => {
      const osc = ctx.createOscillator();
      const gain = ctx.createGain();
      osc.connect(gain);
      gain.connect(ctx.destination);
      osc.type = "sine";
      osc.frequency.setValueAtTime(freq, ctx.currentTime + i * 0.08);
      gain.gain.setValueAtTime(0.1, ctx.currentTime + i * 0.08);
      gain.gain.exponentialRampToValueAtTime(0.01, ctx.currentTime + i * 0.08 + 0.3);
      osc.start(ctx.currentTime + i * 0.08);
      osc.stop(ctx.currentTime + i * 0.08 + 0.3);
    });
  }
}

const soundEngine = new SoundEngine();

// 🎊 Confetti Particle System
interface Particle {
  x: number;
  y: number;
  vx: number;
  vy: number;
  color: string;
  size: number;
  rotation: number;
  rotationSpeed: number;
  life: number;
}

function ConfettiCanvas({ trigger }: { trigger: number }) {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const particlesRef = useRef<Particle[]>([]);
  const animationRef = useRef<number>(0);

  const spawnConfetti = useCallback((x: number, y: number, count: number, colors: string[]) => {
    for (let i = 0; i < count; i++) {
      particlesRef.current.push({
        x,
        y,
        vx: (Math.random() - 0.5) * 15,
        vy: -Math.random() * 15 - 5,
        color: colors[Math.floor(Math.random() * colors.length)],
        size: Math.random() * 8 + 4,
        rotation: Math.random() * Math.PI * 2,
        rotationSpeed: (Math.random() - 0.5) * 0.3,
        life: 1,
      });
    }
  }, []);

  useEffect(() => {
    if (trigger > 0) {
      const canvas = canvasRef.current;
      if (canvas) {
        // Spawn from center-ish
        spawnConfetti(
          canvas.width / 2 + (Math.random() - 0.5) * 200,
          canvas.height / 3,
          50,
          ["#ff6b6b", "#ffd93d", "#6bcb77", "#4d96ff", "#ff6bcb", "#c56bff"]
        );
      }
    }
  }, [trigger, spawnConfetti]);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext("2d");
    if (!ctx) return;

    const animate = () => {
      ctx.clearRect(0, 0, canvas.width, canvas.height);
      
      particlesRef.current = particlesRef.current.filter(p => {
        p.x += p.vx;
        p.y += p.vy;
        p.vy += 0.5; // gravity
        p.rotation += p.rotationSpeed;
        p.life -= 0.015;
        
        if (p.life <= 0) return false;
        
        ctx.save();
        ctx.translate(p.x, p.y);
        ctx.rotate(p.rotation);
        ctx.globalAlpha = p.life;
        ctx.fillStyle = p.color;
        ctx.fillRect(-p.size / 2, -p.size / 2, p.size, p.size * 0.6);
        ctx.restore();
        
        return true;
      });

      if (particlesRef.current.length > 0) {
        animationRef.current = requestAnimationFrame(animate);
      }
    };

    animationRef.current = requestAnimationFrame(animate);
    return () => cancelAnimationFrame(animationRef.current);
  }, [trigger]);

  return (
    <canvas
      ref={canvasRef}
      width={800}
      height={400}
      className="absolute inset-0 pointer-events-none z-50"
      style={{ width: "100%", height: "100%" }}
    />
  );
}

// 🏆 Achievement Badge Component
interface Achievement {
  id: string;
  title: string;
  icon: any;
  color: string;
  description: string;
}

const ACHIEVEMENTS: Achievement[] = [
  { id: "first_blood", title: "First Blood", icon: Target, color: "text-red-400", description: "Found your first vulnerability" },
  { id: "credential_hunter", title: "Credential Hunter", icon: Key, color: "text-yellow-400", description: "Captured 5+ credentials" },
  { id: "critical_hit", title: "Critical Hit", icon: Skull, color: "text-red-500", description: "Found a critical vulnerability" },
  { id: "database_raider", title: "Database Raider", icon: Database, color: "text-blue-400", description: "Gained database access" },
  { id: "combo_master", title: "Combo Master", icon: Flame, color: "text-orange-400", description: "5 findings in 5 minutes" },
  { id: "centurion", title: "Centurion", icon: Trophy, color: "text-amber-400", description: "100+ iterations completed" },
  { id: "unstoppable", title: "Unstoppable", icon: Zap, color: "text-purple-400", description: "10+ findings streak" },
];

function AchievementPopup({ achievement, onClose }: { achievement: Achievement; onClose: () => void }) {
  useEffect(() => {
    soundEngine.playAchievement();
    const timer = setTimeout(onClose, 4000);
    return () => clearTimeout(timer);
  }, [onClose]);

  const Icon = achievement.icon;
  
  return (
    <div className="fixed top-20 left-1/2 -translate-x-1/2 z-[100] animate-bounce-in">
      <div className="bg-gradient-to-r from-amber-900/90 to-yellow-900/90 backdrop-blur-lg rounded-xl p-4 border-2 border-yellow-500/50 shadow-2xl shadow-yellow-500/20">
        <div className="flex items-center gap-4">
          <div className="p-3 rounded-full bg-yellow-500/20 border border-yellow-500/50">
            <Icon className={`w-8 h-8 ${achievement.color}`} />
          </div>
          <div>
            <p className="text-xs text-yellow-300/70 uppercase tracking-wider">Achievement Unlocked!</p>
            <p className="text-xl font-bold text-yellow-100">{achievement.title}</p>
            <p className="text-sm text-yellow-200/70">{achievement.description}</p>
          </div>
          <Star className="w-6 h-6 text-yellow-400 animate-spin-slow" />
        </div>
      </div>
    </div>
  );
}

// 🎯 Finding Card with Animation
interface Finding {
  id: string;
  title: string;
  severity: string;
  type: string;
  location?: string;
  description?: string;
  evidence?: string;
  timestamp: string;
  isNew?: boolean;
}

function FindingCard({ finding, index }: { finding: Finding; index: number }) {
  const [isVisible, setIsVisible] = useState(false);
  
  useEffect(() => {
    const timer = setTimeout(() => setIsVisible(true), index * 100);
    return () => clearTimeout(timer);
  }, [index]);

  const severityConfig: Record<string, { bg: string; border: string; icon: any; glow: string }> = {
    critical: { bg: "bg-red-950/50", border: "border-red-500/50", icon: Skull, glow: "shadow-red-500/30" },
    high: { bg: "bg-orange-950/50", border: "border-orange-500/50", icon: Shield, glow: "shadow-orange-500/30" },
    medium: { bg: "bg-yellow-950/50", border: "border-yellow-500/50", icon: Zap, glow: "shadow-yellow-500/30" },
    low: { bg: "bg-blue-950/50", border: "border-blue-500/50", icon: Target, glow: "shadow-blue-500/20" },
    info: { bg: "bg-slate-800/50", border: "border-slate-500/50", icon: Target, glow: "" },
  };

  const config = severityConfig[finding.severity] || severityConfig.info;
  const Icon = config.icon;

  return (
    <div
      className={`
        transform transition-all duration-500 ease-out
        ${isVisible ? "translate-x-0 opacity-100" : "-translate-x-8 opacity-0"}
        ${finding.isNew ? "animate-pulse-once" : ""}
      `}
    >
      <div className={`
        ${config.bg} ${config.border} ${config.glow}
        border rounded-lg p-3 shadow-lg
        hover:scale-[1.02] transition-transform cursor-pointer
        ${finding.isNew ? "ring-2 ring-white/30" : ""}
      `}>
        <div className="flex items-start gap-3">
          <div className={`p-2 rounded-lg ${config.bg} border ${config.border}`}>
            <Icon className="w-4 h-4" />
          </div>
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-2">
              <span className={`
                text-[10px] font-bold uppercase px-2 py-0.5 rounded
                ${config.bg} ${config.border} border
              `}>
                {finding.severity}
              </span>
              <span className="text-xs text-slate-400">{finding.type}</span>
            </div>
            <p className="text-sm font-medium mt-1 truncate">{finding.title}</p>
            {finding.description && (() => {
              const lines = finding.description.split("\n").filter(Boolean);
              const prose = lines[0] || "";
              const kvLine = lines.length > 1 ? lines[1] : "";
              const kvPairs = kvLine ? kvLine.split(" | ").filter(Boolean) : [];
              return (
                <div className="mt-1 space-y-1">
                  {prose && <p className="text-xs text-slate-300/80">{prose}</p>}
                  {kvPairs.length > 0 && (
                    <div className="flex flex-wrap gap-1.5">
                      {kvPairs.map((kv: string, j: number) => {
                        const [label, ...rest] = kv.split(":");
                        const value = rest.join(":").trim();
                        return (
                          <span key={j} className="inline-flex items-center gap-1 text-[10px] px-1.5 py-0.5 rounded bg-black/30 border border-white/5">
                            <span className="text-slate-500">{label.trim()}</span>
                            {value && <span className="text-slate-300">{value}</span>}
                          </span>
                        );
                      })}
                    </div>
                  )}
                </div>
              );
            })()}
            {finding.evidence && !finding.description && (
              <p className="text-xs text-slate-400/60 mt-0.5 line-clamp-2 font-mono">{finding.evidence}</p>
            )}
            {finding.location && (
              <p className="text-xs text-slate-500 truncate mt-0.5">📍 {finding.location}</p>
            )}
          </div>
          {finding.isNew && (
            <span className="px-2 py-0.5 text-[10px] font-bold bg-green-500/20 text-green-400 rounded-full animate-pulse">
              NEW
            </span>
          )}
        </div>
      </div>
    </div>
  );
}

// 🔥 Streak Counter
function StreakCounter({ streak, maxStreak }: { streak: number; maxStreak: number }) {
  if (streak < 2) return null;
  
  return (
    <div className="flex items-center gap-2 px-3 py-1.5 rounded-full bg-gradient-to-r from-orange-600/30 to-red-600/30 border border-orange-500/30">
      <Flame className={`w-4 h-4 ${streak >= 5 ? "text-red-400 animate-pulse" : "text-orange-400"}`} />
      <span className="text-sm font-bold text-orange-200">
        {streak}x Streak
      </span>
      {streak >= maxStreak && streak > 1 && (
        <span className="text-[10px] bg-yellow-500/30 text-yellow-300 px-1.5 rounded">BEST!</span>
      )}
    </div>
  );
}

// 💪 Encouragement Messages - Hacker themed motivational messages
const ENCOURAGEMENT_MESSAGES = {
  // General hunting messages (default pool)
  idle: [
    "🔍 Scanning for weaknesses...",
    "💉 Injecting payloads...",
    "🕵️ The hunt continues...",
    "⚡ Exploiting like a pro...",
    "🎯 Zeroing in on targets...",
    "🔓 Breaking through defenses...",
    "🐛 Bug hunting mode activated...",
    "🌐 Mapping the attack surface...",
    "🔐 Picking digital locks...",
    "💀 Death by 1000 packets...",
    "🧠 Thinking like an attacker...",
    "🕸️ Spinning the web of exploits...",
    "⌨️ Hacking the mainframe... jk 😏",
    "🎰 Rolling for critical vulns...",
    "🔬 Deep packet inspection active...",
    "🗺️ Charting uncharted territory...",
    "💫 Fuzzing with finesse...",
    "🚀 Payload delivery in progress...",
    "🔮 Divining security flaws...",
    "⚔️ Engaging cyber warfare mode...",
    "🏴‍☠️ Arr, hunting for treasure...",
    "🐍 Slithering through defenses...",
    "🎪 Welcome to the exploit circus...",
    "🌙 Burning the midnight oil...",
    "☕ Fueled by coffee and curiosity...",
  ],
  // Messages when on a finding streak (streak >= 3)
  streak: [
    "🔥 You're on fire! Keep it up!",
    "⚡ Unstoppable finding machine!",
    "💥 COMBO BREAKER... wait, you ARE the combo!",
    "🌟 The vulns just keep coming!",
    "🎯 Bullseye after bullseye!",
    "🏆 Hall of fame material right here!",
    "🚂 ALL ABOARD THE VULN TRAIN!",
    "💪 Flexing on these defenses!",
  ],
  // Messages for high iteration count (iteration >= 50)
  endurance: [
    "🏃 Marathon runner vibes...",
    "💎 Diamonds are made under pressure...",
    "🦾 Persistence is key!",
    "🌊 Deep dive mode engaged...",
    "⏳ Patience pays off...",
    "🔋 Still running strong!",
    "🏔️ Climbing the vulnerability mountain...",
    "🐢 Slow and steady wins the race...",
  ],
  // Messages when no findings yet (findings.length === 0)
  searching: [
    "🔭 Scanning the horizon...",
    "🧭 Navigating the codebase...",
    "🎣 Casting the net wide...",
    "🌱 Planting seeds of chaos...",
    "🔦 Shining light into dark corners...",
    "🗝️ Every lock has a key...",
    "🎲 Fortune favors the bold...",
    "🐾 Following the trail...",
  ],
  // Messages after finding something critical
  critical: [
    "🎉 JACKPOT! Critical finding!",
    "💀 FATALITY! Critical discovered!",
    "🚨 RED ALERT! Big one incoming!",
    "🏆 THIS IS THE ONE!",
    "⭐ LEGENDARY FIND!",
  ],
};

// 💬 Encouragement Banner Component with typing animation
interface EncouragementBannerProps {
  streak: number;
  iteration: number;
  findingsCount: number;
  lastSeverity?: string;
}

export function EncouragementBanner({ streak, iteration, findingsCount, lastSeverity }: EncouragementBannerProps) {
  const [currentMessage, setCurrentMessage] = useState("");
  const [displayedText, setDisplayedText] = useState("");
  const [isTyping, setIsTyping] = useState(false);
  const [isFading, setIsFading] = useState(false);
  const intervalRef = useRef<NodeJS.Timeout | null>(null);
  const typeIntervalRef = useRef<NodeJS.Timeout | null>(null);

  // Get appropriate message pool based on context
  const getMessagePool = useCallback(() => {
    // If last finding was critical, show critical message occasionally
    if (lastSeverity === "critical" && Math.random() < 0.5) {
      return ENCOURAGEMENT_MESSAGES.critical;
    }
    // If on a streak, favor streak messages
    if (streak >= 3) {
      return Math.random() < 0.6 
        ? ENCOURAGEMENT_MESSAGES.streak 
        : ENCOURAGEMENT_MESSAGES.idle;
    }
    // If high iteration count, show endurance messages
    if (iteration >= 50) {
      return Math.random() < 0.4 
        ? ENCOURAGEMENT_MESSAGES.endurance 
        : ENCOURAGEMENT_MESSAGES.idle;
    }
    // If no findings yet, show searching messages
    if (findingsCount === 0) {
      return Math.random() < 0.5 
        ? ENCOURAGEMENT_MESSAGES.searching 
        : ENCOURAGEMENT_MESSAGES.idle;
    }
    // Default to idle messages
    return ENCOURAGEMENT_MESSAGES.idle;
  }, [streak, iteration, findingsCount, lastSeverity]);

  // Pick a random message from the pool
  const pickNewMessage = useCallback(() => {
    const pool = getMessagePool();
    const randomIndex = Math.floor(Math.random() * pool.length);
    return pool[randomIndex];
  }, [getMessagePool]);

  // Typing animation effect
  useEffect(() => {
    if (!currentMessage) return;
    
    setDisplayedText("");
    setIsTyping(true);
    let charIndex = 0;
    
    // Clear any existing typing interval
    if (typeIntervalRef.current) {
      clearInterval(typeIntervalRef.current);
    }
    
    typeIntervalRef.current = setInterval(() => {
      if (charIndex < currentMessage.length) {
        setDisplayedText(currentMessage.substring(0, charIndex + 1));
        charIndex++;
      } else {
        setIsTyping(false);
        if (typeIntervalRef.current) {
          clearInterval(typeIntervalRef.current);
        }
      }
    }, 35); // Typing speed - 35ms per character
    
    return () => {
      if (typeIntervalRef.current) {
        clearInterval(typeIntervalRef.current);
      }
    };
  }, [currentMessage]);

  // Rotate messages every 8-10 seconds
  useEffect(() => {
    // Initial message
    setCurrentMessage(pickNewMessage());
    
    const rotateMessage = () => {
      // Start fade out
      setIsFading(true);
      
      // After fade out, change message and fade in
      setTimeout(() => {
        setCurrentMessage(pickNewMessage());
        setIsFading(false);
      }, 400); // Match fade out duration
    };
    
    // Random interval between 8-10 seconds
    const scheduleNext = () => {
      const delay = 8000 + Math.random() * 2000; // 8-10 seconds
      intervalRef.current = setTimeout(() => {
        rotateMessage();
        scheduleNext();
      }, delay);
    };
    
    scheduleNext();
    
    return () => {
      if (intervalRef.current) {
        clearTimeout(intervalRef.current);
      }
    };
  }, [pickNewMessage]);

  return (
    <div className="relative overflow-hidden rounded-lg bg-gradient-to-r from-indigo-950/40 via-purple-950/40 to-indigo-950/40 border border-indigo-500/20 px-4 py-3 mb-4">
      {/* Subtle animated background shimmer */}
      <div className="absolute inset-0 bg-gradient-to-r from-transparent via-white/5 to-transparent animate-shimmer" />
      
      <div className={`
        relative flex items-center gap-3
        transition-opacity duration-400 ease-in-out
        ${isFading ? "opacity-0" : "opacity-100"}
      `}>
        {/* Pulsing indicator */}
        <div className="relative flex-shrink-0">
          <div className="w-2 h-2 rounded-full bg-green-400 animate-pulse" />
          <div className="absolute inset-0 w-2 h-2 rounded-full bg-green-400 animate-ping opacity-75" />
        </div>
        
        {/* Message with typing cursor */}
        <div className="flex-1 min-w-0">
          <p className="text-sm font-medium text-indigo-100/90 truncate">
            {displayedText}
            {isTyping && (
              <span className="inline-block w-0.5 h-4 bg-indigo-400 ml-0.5 animate-blink align-middle" />
            )}
          </p>
        </div>
        
        {/* Context indicator badges */}
        <div className="flex gap-2 flex-shrink-0">
          {streak >= 3 && (
            <span className="text-[10px] px-2 py-0.5 rounded-full bg-orange-500/20 text-orange-300 border border-orange-500/30">
              🔥 {streak}x
            </span>
          )}
          {iteration >= 50 && (
            <span className="text-[10px] px-2 py-0.5 rounded-full bg-purple-500/20 text-purple-300 border border-purple-500/30">
              ⚡ {iteration}
            </span>
          )}
        </div>
      </div>
    </div>
  );
}

// 📊 Main Dopamine Feed Component
interface DopamineFeedProps {
  findings: Finding[];
  credentials: number;
  iteration: number;
  maxIterations: number;
  onAchievement?: (achievement: Achievement) => void;
  compact?: boolean;
}

// 📱 Vibration patterns for different severities (ms)
const VIBRATION_PATTERNS: Record<string, number[]> = {
  info: [50],
  low: [50, 30, 50],
  medium: [100, 50, 100],
  high: [150, 50, 150, 50, 150],
  critical: [200, 100, 200, 100, 300],
};

// 📳 Shake class mapping by severity
const SHAKE_CLASSES: Record<string, string> = {
  info: "animate-shake-light",
  low: "animate-shake-light",
  medium: "animate-shake-medium",
  high: "animate-shake-heavy",
  critical: "animate-shake-critical",
};

// 🎯 Shake durations (ms) for clearing animation class
const SHAKE_DURATIONS: Record<string, number> = {
  info: 300,
  low: 300,
  medium: 350,
  high: 400,
  critical: 500,
};

// 📳 Trigger haptic feedback via Vibration API
function triggerHaptic(severity: string) {
  if (typeof navigator !== "undefined" && "vibrate" in navigator) {
    const pattern = VIBRATION_PATTERNS[severity] || VIBRATION_PATTERNS.info;
    try {
      navigator.vibrate(pattern);
    } catch {
      // Vibration API not supported or blocked
    }
  }
}

export function DopamineFeed({ findings, credentials, iteration, maxIterations, onAchievement, compact = false }: DopamineFeedProps) {
  // Get settings from localStorage
  const { settings, updateSettings } = useDopamineSettings();
  
  const [confettiTrigger, setConfettiTrigger] = useState(0);
  const [streak, setStreak] = useState(0);
  const [maxStreak, setMaxStreak] = useState(0);
  const [activeAchievement, setActiveAchievement] = useState<Achievement | null>(null);
  const [unlockedAchievements, setUnlockedAchievements] = useState<Set<string>>(new Set());
  const [shakeClass, setShakeClass] = useState<string>("");
  const [lastSeverity, setLastSeverity] = useState<string | undefined>(undefined);
  const lastFindingsCount = useRef(0);
  const lastFindingTime = useRef(Date.now());
  const streakTimeoutRef = useRef<NodeJS.Timeout | null>(null);
  const shakeTimeoutRef = useRef<NodeJS.Timeout | null>(null);
  
  // Sync sound engine with settings
  useEffect(() => {
    soundEngine.setEnabled(settings.soundEnabled);
    soundEngine.setVolume(settings.soundVolume / 100);
  }, [settings.soundEnabled, settings.soundVolume]);

  // Check and unlock achievements
  const checkAchievements = useCallback((findingsCount: number, latestFinding?: Finding) => {
    const newAchievements: Achievement[] = [];
    
    if (findingsCount === 1 && !unlockedAchievements.has("first_blood")) {
      newAchievements.push(ACHIEVEMENTS.find(a => a.id === "first_blood")!);
    }
    if (credentials >= 5 && !unlockedAchievements.has("credential_hunter")) {
      newAchievements.push(ACHIEVEMENTS.find(a => a.id === "credential_hunter")!);
    }
    if (latestFinding?.severity === "critical" && !unlockedAchievements.has("critical_hit")) {
      newAchievements.push(ACHIEVEMENTS.find(a => a.id === "critical_hit")!);
    }
    if (iteration >= 100 && !unlockedAchievements.has("centurion")) {
      newAchievements.push(ACHIEVEMENTS.find(a => a.id === "centurion")!);
    }
    if (streak >= 10 && !unlockedAchievements.has("unstoppable")) {
      newAchievements.push(ACHIEVEMENTS.find(a => a.id === "unstoppable")!);
    }
    
    if (newAchievements.length > 0) {
      const achievement = newAchievements[0];
      setUnlockedAchievements(prev => {
        const next = new Set(prev);
        next.add(achievement.id);
        return next;
      });
      setActiveAchievement(achievement);
      setConfettiTrigger(t => t + 1);
      onAchievement?.(achievement);
    }
  }, [credentials, iteration, streak, unlockedAchievements, onAchievement]);

  // Check for new findings and trigger effects
  useEffect(() => {
    const newCount = findings.length;
    if (newCount > lastFindingsCount.current) {
      const diff = newCount - lastFindingsCount.current;
      const latestFinding = findings[0]; // Assuming sorted newest first
      
      // Update streak
      const now = Date.now();
      const timeSinceLastFinding = now - lastFindingTime.current;
      
      if (timeSinceLastFinding < 60000) { // Within 1 minute
        setStreak(s => {
          const newStreak = s + diff;
          if (newStreak > maxStreak) setMaxStreak(newStreak);
          return newStreak;
        });
      } else {
        setStreak(diff);
      }
      lastFindingTime.current = now;
      
      // Reset streak after 60s of no findings
      if (streakTimeoutRef.current) clearTimeout(streakTimeoutRef.current);
      streakTimeoutRef.current = setTimeout(() => setStreak(0), 60000);
      
      // Track last severity for encouragement messages
      if (latestFinding?.severity) {
        setLastSeverity(latestFinding.severity);
        // Clear critical severity after 15 seconds so we don't keep showing critical messages
        if (latestFinding.severity === "critical") {
          setTimeout(() => setLastSeverity(undefined), 15000);
        }
      }
      
      // Play appropriate sound (if enabled in settings)
      if (settings.soundEnabled) {
        if (latestFinding?.severity === "critical") {
          soundEngine.playCritical();
        } else if (latestFinding?.severity === "high") {
          soundEngine.playHighSeverity();
        } else {
          soundEngine.playFind();
        }
        
        // Play combo sound if streak > 2
        if (streak > 2) {
          setTimeout(() => soundEngine.playCombo(streak), 300);
        }
      }
      
      // Trigger confetti for critical findings (if enabled)
      if (settings.confettiEnabled && latestFinding?.severity === "critical") {
        setConfettiTrigger(t => t + 1);
      }
      
      // 📱 Trigger shake animation (if enabled)
      const severity = latestFinding?.severity || "info";
      if (settings.shakeEnabled) {
        const shakeClassName = SHAKE_CLASSES[severity] || SHAKE_CLASSES.info;
        const shakeDuration = SHAKE_DURATIONS[severity] || SHAKE_DURATIONS.info;
        
        // Clear any existing shake timeout
        if (shakeTimeoutRef.current) clearTimeout(shakeTimeoutRef.current);
        
        // Apply shake class
        setShakeClass(shakeClassName);
        
        // Remove shake class after animation completes
        shakeTimeoutRef.current = setTimeout(() => {
          setShakeClass("");
        }, shakeDuration);
      }
      
      // Trigger haptic feedback on mobile (if enabled)
      if (settings.hapticEnabled) {
        triggerHaptic(severity);
      }
      
      // Browser notification (if enabled)
      if (settings.notificationsEnabled && Notification.permission === "granted") {
        const severityLabel = severity.toUpperCase();
        new Notification(`🎯 TazoSploit: ${severityLabel} Finding!`, {
          body: latestFinding?.title || "New vulnerability discovered",
          icon: "/favicon.ico",
        });
      }
      
      // Check achievements (if enabled)
      if (settings.achievementsEnabled) {
        checkAchievements(newCount, latestFinding);
      }
    }
    lastFindingsCount.current = newCount;
  }, [
    checkAchievements,
    credentials,
    findings,
    maxStreak,
    settings.achievementsEnabled,
    settings.confettiEnabled,
    settings.hapticEnabled,
    settings.notificationsEnabled,
    settings.shakeEnabled,
    settings.soundEnabled,
    streak,
  ]);

  // Sound toggle - quick access (also configurable in Settings)
  const toggleSound = () => {
    updateSettings({ soundEnabled: !settings.soundEnabled });
  };

  return (
    <div className={`relative ${settings.shakeEnabled ? shakeClass : ""}`}>
      {settings.confettiEnabled && <ConfettiCanvas trigger={confettiTrigger} />}
      
      {settings.achievementsEnabled && activeAchievement && (
        <AchievementPopup 
          achievement={activeAchievement} 
          onClose={() => setActiveAchievement(null)} 
        />
      )}
      
      {/* Header with streak and sound toggle */}
      <div className="flex items-center justify-between mb-4">
      <div className="flex items-center gap-3">
        <h3 className="text-sm font-semibold flex items-center gap-2">
          <Target className="w-4 h-4 text-indigo-400" />
          Live Findings Feed
        </h3>
        <StreakCounter streak={streak} maxStreak={maxStreak} />
        <span className="text-[10px] text-[var(--text-dim)]">
          Iter {iteration}/{maxIterations}
        </span>
      </div>
        <button
          onClick={toggleSound}
          className={`p-2 rounded-lg transition ${settings.soundEnabled ? "bg-indigo-600/20 text-indigo-400" : "bg-slate-700/30 text-slate-500"}`}
          title={settings.soundEnabled ? "Mute sounds" : "Enable sounds"}
        >
          {settings.soundEnabled ? "🔊" : "🔇"}
        </button>
      </div>
      
      {/* Encouragement Banner - rotating motivational messages */}
      {settings.encouragementEnabled && (
        <EncouragementBanner 
          streak={streak}
          iteration={iteration}
          findingsCount={findings.length}
          lastSeverity={lastSeverity}
        />
      )}
      
      {/* Findings List — hidden in compact mode (Discoveries panel is the single source of truth) */}
      {!compact && (
        <div className="space-y-2 max-h-[400px] overflow-y-auto pr-2 custom-scrollbar">
          {findings.length === 0 ? (
            <div className="text-center py-8 text-slate-500">
              <Target className="w-8 h-8 mx-auto mb-2 opacity-50" />
              <p>Hunting for vulnerabilities...</p>
              <p className="text-xs mt-1">Findings will appear here with 🎵 sound alerts</p>
            </div>
          ) : (
            findings.slice(0, 20).map((finding, i) => (
              <FindingCard key={finding.id || i} finding={finding} index={i} />
            ))
          )}
        </div>
      )}
      {compact && findings.length > 0 && (
        <div className="text-xs text-[var(--text-dim)] mt-1">
          {findings.length} finding{findings.length !== 1 ? "s" : ""} — see Discoveries below ↓
        </div>
      )}
      
      {/* Achievement badges earned */}
      {unlockedAchievements.size > 0 && (
        <div className="mt-4 pt-4 border-t border-slate-700/50">
          <p className="text-xs text-slate-500 mb-2">Achievements Unlocked</p>
          <div className="flex gap-2 flex-wrap">
            {ACHIEVEMENTS.filter(a => unlockedAchievements.has(a.id)).map(achievement => {
              const Icon = achievement.icon;
              return (
                <div
                  key={achievement.id}
                  className="p-2 rounded-lg bg-amber-900/30 border border-amber-500/30"
                  title={achievement.description}
                >
                  <Icon className={`w-4 h-4 ${achievement.color}`} />
                </div>
              );
            })}
          </div>
        </div>
      )}
    </div>
  );
}

// Export sound engine for external use
export { soundEngine };
