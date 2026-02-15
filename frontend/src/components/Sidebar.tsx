"use client";
import Link from "next/link";
import { usePathname } from "next/navigation";
import { useState, useEffect, useCallback } from "react";
import {
  LayoutDashboard,
  Crosshair,
  FileText,
  Settings,
  Network,
  Menu,
  X,
} from "lucide-react";
import { cn } from "@/lib/utils";
import { AnimatedLogo } from "./AnimatedLogo";

const links = [
  { href: "/", label: "Dashboard", icon: LayoutDashboard },
  { href: "/pentests", label: "Pentests", icon: Crosshair },
  { href: "/agents", label: "Agents", icon: Network },
  { href: "/reports", label: "Reports", icon: FileText },
  { href: "/settings", label: "Settings", icon: Settings },
];

export default function Sidebar() {
  const pathname = usePathname();
  const [open, setOpen] = useState(false);
  const [isMobile, setIsMobile] = useState(false);

  useEffect(() => {
    const check = () => setIsMobile(window.innerWidth < 768);
    check();
    window.addEventListener("resize", check);
    return () => window.removeEventListener("resize", check);
  }, []);

  // Close sidebar on route change (mobile)
  useEffect(() => {
    if (isMobile) setOpen(false);
  }, [pathname, isMobile]);

  const toggle = useCallback(() => setOpen((o) => !o), []);

  return (
    <>
      {/* Hamburger button — mobile only */}
      {isMobile && !open && (
        <button
          onClick={toggle}
          className="fixed top-4 left-4 z-50 p-2 rounded-lg bg-[var(--surface)] border border-[var(--border)] text-white"
          aria-label="Open menu"
        >
          <Menu className="w-5 h-5" />
        </button>
      )}

      {/* Overlay backdrop — mobile only */}
      {isMobile && open && (
        <div
          className="fixed inset-0 bg-black/50 z-40"
          onClick={toggle}
        />
      )}

      {/* Sidebar */}
      <aside
        className={cn(
          "fixed left-0 top-0 h-screen w-56 bg-[var(--surface)] border-r border-[var(--border)] flex flex-col z-50 transition-transform duration-200",
          isMobile && !open && "-translate-x-full"
        )}
      >
        <div className="flex items-center justify-center px-4 py-3 border-b border-[var(--border)]">
          <div className="w-full">
            <AnimatedLogo />
          </div>
          {isMobile && (
            <button onClick={toggle} className="absolute right-4 text-[var(--text-dim)] hover:text-white" aria-label="Close menu">
              <X className="w-5 h-5" />
            </button>
          )}
        </div>
        <nav className="flex-1 py-4 space-y-1">
          {links.map((l) => {
            const active = pathname === l.href || (l.href !== "/" && pathname.startsWith(l.href));
            return (
              <Link
                key={l.href}
                href={l.href}
                className={cn(
                  "flex items-center gap-3 px-4 py-2.5 text-sm transition-colors",
                  active
                    ? "bg-indigo-500/10 text-indigo-400 border-r-2 border-indigo-500"
                    : "text-[var(--text-dim)] hover:text-white hover:bg-white/5"
                )}
              >
                <l.icon className="w-4 h-4" />
                {l.label}
              </Link>
            );
          })}
        </nav>
        <div className="p-4 border-t border-[var(--border)] text-xs text-[var(--text-dim)]">
          v2.0.0 &middot; SaaS
        </div>
      </aside>
    </>
  );
}
