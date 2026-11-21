'use client';

import { useEffect, useState } from 'react';
import Link from 'next/link';

interface ThreatItem {
  id: string;
  title: string;
  category: string;
  severity: string;
}

export default function ThreatTicker() {
  const [threats, setThreats] = useState<ThreatItem[]>([]);

  useEffect(() => {
    fetch('/api/stats')
      .then((res) => res.json())
      .then((data) => {
        if (data.success && data.stats?.recentThreats) {
          setThreats(data.stats.recentThreats);
        }
      })
      .catch(() => {});
  }, []);

  if (threats.length === 0) return null;

  return (
    <div className="bg-slate-900 border-b border-slate-800/80 px-4 py-2 overflow-hidden flex items-center gap-3 text-xs">
      <div className="flex items-center gap-1.5 shrink-0 px-2 py-0.5 rounded bg-rose-950/80 text-rose-400 font-semibold border border-rose-800/50">
        <span className="w-2 h-2 rounded-full bg-rose-500 animate-pulse" />
        <span>LIVE THREAT RADAR</span>
      </div>
      <div className="flex items-center gap-6 overflow-x-auto no-scrollbar whitespace-nowrap text-slate-300">
        {threats.map((t) => (
          <Link
            key={t.id}
            href={`/community/${t.id}`}
            className="flex items-center gap-2 hover:text-cyan-400 transition-colors"
          >
            <span
              className={`px-1.5 py-0.5 rounded text-[10px] font-bold ${
                t.severity === 'CRITICAL'
                  ? 'bg-red-950 text-red-400 border border-red-800/50'
                  : 'bg-amber-950 text-amber-400 border border-amber-800/50'
              }`}
            >
              {t.category.replace(/_/g, ' ')}
            </span>
            <span className="truncate max-w-xs">{t.title}</span>
          </Link>
        ))}
      </div>
    </div>
  );
}
