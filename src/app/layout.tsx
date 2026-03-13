import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "NTAV SecuLab V2.0",
  description: "Never Trust, Always Verify Security Platform",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="ko">
      <body className="antialiased ntav-gradient min-h-screen">
        <nav className="border-b border-white/10 p-4 sticky top-0 bg-background/80 backdrop-blur-md z-50">
          <div className="container mx-auto flex justify-between items-center">
            <h1 className="text-xl font-bold tracking-tighter text-blue-500">NTAV SecuLab V2.0</h1>
            <div className="space-x-6 text-sm">
              <span className="text-zinc-400">시스템점검실</span>
              <span className="text-zinc-400">위협분석실</span>
              <span className="text-zinc-400">코덱연구소</span>
              <span className="bg-blue-600/20 text-blue-400 px-3 py-1 rounded-full border border-blue-500/30">CERT</span>
            </div>
          </div>
        </nav>
        <main className="container mx-auto p-6">
          {children}
        </main>
      </body>
    </html>
  );
}
