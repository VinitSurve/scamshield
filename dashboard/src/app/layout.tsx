import type { Metadata } from 'next';
import { Suspense } from 'react';
import './globals.css';
import Navigation from '@/components/Navigation';
import ThreatTicker from '@/components/ThreatTicker';

export const metadata: Metadata = {
  title: 'ScamShield — Community Threat Intelligence & Automated Testing Platform',
  description: 'Crowdsourced cybersecurity defense against digital arrest, banking KYC smishing, electricity cutoff, and UPI fraud across India.',
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en" className="dark h-full antialiased">
      <body className="min-h-full flex flex-col bg-slate-950 text-slate-100 selection:bg-cyan-500/30 selection:text-cyan-200">
        <Suspense fallback={<div className="h-16 bg-slate-950 border-b border-slate-800" />}>
          <Navigation />
        </Suspense>
        <Suspense fallback={null}>
          <ThreatTicker />
        </Suspense>
        <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-6">
          {children}
        </main>
        <footer className="border-t border-slate-800/80 bg-slate-950 py-6 text-center text-xs text-slate-500">
          <div className="max-w-7xl mx-auto px-4 flex flex-col sm:flex-row items-center justify-between gap-4">
            <div className="flex items-center gap-2">
              <span className="font-semibold text-slate-400">ScamShield Cyber Defense</span>
              <span>• Multi-Agent AI & ML Robustness Lab</span>
            </div>
            <div className="flex items-center gap-4 text-slate-400">
              <span>National Cybercrime Helpline: <strong>1930</strong></span>
              <span>•</span>
              <a href="https://cybercrime.gov.in" target="_blank" rel="noopener noreferrer" className="hover:text-cyan-400 underline">
                cybercrime.gov.in
              </a>
            </div>
          </div>
        </footer>
      </body>
    </html>
  );
}
