import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "TazoSploit - AI Pentest Platform",
  description: "AI-powered penetration testing SaaS",
};

import { DopamineProvider } from "@/context/DopamineContext";

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" className="dark">
      <body>
        <DopamineProvider>
          {children}
        </DopamineProvider>
      </body>
    </html>
  );
}
