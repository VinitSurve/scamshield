import React from 'react';
import { ShieldCheck, AlertTriangle, ShieldAlert, Globe, Lock, Unlock, Info } from 'lucide-react';
import { ReputationVerdict } from '../../types/threat';

interface StatusCardProps {
  verdict: ReputationVerdict;
  protectionActive: boolean;
  isWhitelisted: boolean;
  t: Record<string, string>;
}

export const StatusCard: React.FC<StatusCardProps> = ({
  verdict,
  protectionActive,
  isWhitelisted,
  t,
}) => {
  const isHttps = verdict.canonicalUrl.startsWith('https://');

  const getBadgeConfig = () => {
    if (!protectionActive) {
      return {
        bg: 'bg-slate-800 text-slate-300 border-slate-700',
        text: t.protectionPaused,
        icon: <ShieldAlert className="w-4 h-4 text-slate-400" />,
      };
    }
    if (isWhitelisted) {
      return {
        bg: 'bg-blue-900/30 text-blue-300 border-blue-700/50',
        text: 'Whitelisted',
        icon: <ShieldCheck className="w-4 h-4 text-blue-400" />,
      };
    }
    switch (verdict.severity) {
      case 'SAFE':
        return {
          bg: 'bg-threat-safeBg text-threat-safe border-emerald-500/30',
          text: t.statusProtected,
          icon: <ShieldCheck className="w-4 h-4 text-threat-safe" />,
        };
      case 'SUSPICIOUS':
        return {
          bg: 'bg-threat-warningBg text-threat-warning border-amber-500/30',
          text: t.statusSuspicious,
          icon: <AlertTriangle className="w-4 h-4 text-threat-warning" />,
        };
      case 'HIGH':
      case 'CRITICAL':
        return {
          bg: 'bg-threat-dangerBg text-threat-danger border-red-500/30',
          text: t.statusDangerous,
          icon: <ShieldAlert className="w-4 h-4 text-threat-danger" />,
        };
      default:
        return {
          bg: 'bg-threat-neutralBg text-slate-300 border-slate-700',
          text: t.statusUnknown,
          icon: <Info className="w-4 h-4 text-slate-400" />,
        };
    }
  };

  const badge = getBadgeConfig();

  return (
    <div className="p-4 space-y-3.5">
      {/* Current Domain Box */}
      <div className="bg-shield-card border border-shield-border rounded-xl p-3 space-y-2 shadow-sm">
        <div className="flex items-center justify-between">
          <div className="flex items-center space-x-1.5 overflow-hidden">
            <Globe className="w-4 h-4 text-slate-400 shrink-0" />
            <span
              className="font-mono text-xs font-semibold text-white truncate max-w-[220px]"
              title={verdict.domain}
            >
              {verdict.domain || 'No active website'}
            </span>
          </div>

          <div className="flex items-center space-x-1 text-[11px] text-slate-400">
            {isHttps ? (
              <span className="flex items-center text-emerald-400 space-x-0.5" title="Secure TLS connection">
                <Lock className="w-3 h-3" />
                <span>TLS</span>
              </span>
            ) : (
              <span className="flex items-center text-amber-400 space-x-0.5" title="Insecure HTTP">
                <Unlock className="w-3 h-3" />
                <span>HTTP</span>
              </span>
            )}
          </div>
        </div>

        {/* Status Pill */}
        <div className={`flex items-center space-x-2 px-2.5 py-1.5 rounded-lg border text-xs font-semibold ${badge.bg}`}>
          {badge.icon}
          <span>{badge.text}</span>
          {verdict.category && verdict.category !== 'UNKNOWN' && (
            <span className="ml-auto text-[10px] uppercase font-mono px-1.5 py-0.5 rounded bg-black/30">
              {verdict.category}
            </span>
          )}
        </div>
      </div>

      {/* Risk Assessment Meter */}
      <div className="bg-shield-card border border-shield-border rounded-xl p-3 space-y-2">
        <div className="flex justify-between items-center text-xs">
          <span className="text-slate-400 font-medium">{t.riskScore}</span>
          <span className="font-mono font-bold text-white">
            {Math.round(verdict.riskScore * 100)}%
          </span>
        </div>
        <div className="w-full bg-shield-dark rounded-full h-2 overflow-hidden border border-shield-border/60">
          <div
            className={`h-full transition-all duration-500 rounded-full ${
              verdict.riskScore > 0.7
                ? 'bg-threat-danger'
                : verdict.riskScore > 0.3
                ? 'bg-threat-warning'
                : 'bg-threat-safe'
            }`}
            style={{ width: `${Math.max(verdict.riskScore * 100, 4)}%` }}
          />
        </div>

        {/* Evidence List */}
        <div className="pt-1 space-y-1.5">
          <span className="text-[11px] font-semibold text-slate-300 uppercase tracking-wider block">
            {t.evidenceHeader}
          </span>
          {verdict.evidence && verdict.evidence.length > 0 ? (
            <ul className="space-y-1 text-xs text-slate-300">
              {verdict.evidence.map((item, idx) => (
                <li key={idx} className="flex items-start space-x-1.5 text-[11px] leading-relaxed">
                  <span className="text-shield-accent shrink-0 mt-0.5">•</span>
                  <span>{item}</span>
                </li>
              ))}
            </ul>
          ) : (
            <p className="text-[11px] text-slate-400 italic">{t.noThreatsDetected}</p>
          )}
        </div>
      </div>
    </div>
  );
};
