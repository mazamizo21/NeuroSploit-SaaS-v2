"use client";
import { useEffect, useState } from "react";
import { getToken } from "@/lib/api";
import Sidebar from "@/components/Sidebar";
import LoginModal from "@/components/LoginModal";

export default function AppShell({ children }: { children: React.ReactNode }) {
  const [authed, setAuthed] = useState<boolean | null>(null);

  useEffect(() => {
    const syncAuth = () => setAuthed(!!getToken());
    syncAuth();
    if (typeof window === "undefined") return;
    const onStorage = (e: StorageEvent) => {
      if (e.key === "token") syncAuth();
    };
    window.addEventListener("storage", onStorage);
    window.addEventListener("auth-changed", syncAuth as EventListener);
    return () => {
      window.removeEventListener("storage", onStorage);
      window.removeEventListener("auth-changed", syncAuth as EventListener);
    };
  }, []);

  if (authed === null) return null; // loading

  if (!authed) {
    return <LoginModal onLogin={() => setAuthed(true)} />;
  }

  return (
    <div className="flex min-h-screen">
      <Sidebar />
      <main className="md:ml-56 flex-1 p-4 pt-16 md:pt-6 md:p-6">{children}</main>
    </div>
  );
}
