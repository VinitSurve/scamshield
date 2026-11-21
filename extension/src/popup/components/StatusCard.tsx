import React, { useState } from 'react';
import {
  ShieldCheck,
  AlertTriangle,
  ShieldAlert,
  Globe,
  Lock,
  Unlock,
  Info,
  Clock,
  Zap,
  CheckCircle2,
  XCircle,
  HelpCircle,
  ChevronDown,
  ChevronUp,
} from 'lucide-react';
import { ReputationVerdict } from '../../types/threat';

interface StatusCardProps {
  verdict: ReputationVerdict;
  protectionActive: boolean;
  isWhitelisted: boolean;
  isScanning?: boolean;
  scanMessage?: string | null;
  scanError?: string | null;
  onScanAgain?: () => void;
  t: Record<string, string>;
}

export const StatusCard: React.FC<StatusCardProps> = ({
  verdict,
  protectionActive,
  isWhitelisted,
  isScanning,
  scanMessage,
  scanError,
  onScanAgain,
  t,
}) => {
  const [showChecks, setShowChecks] = useState(false);
  const isHttps = verdict.canonicalUrl?.startsWith('https://');

  const getBadgeConfig = () => {
    if (!protectionActive) {
      return {
        bg: 'bg-slate-800 text-slate-300 border-slate-700',
        text: t.protectionPaused,
        subtext: 'Shield paused',
        icon: <ShieldAlert className="w-4 h-4 text-slate-400" />,
      };
    }
    if (isWhitelisted) {
      return {
        bg: 'bg-blue-900/30 text-blue-300 border-blue-700/50',
        text: 'User Whitelisted',
        subtext: 'Bypasses scanning rules',
        icon: <ShieldCheck className="w-4 h-4 text-blue-400" />,
      };
    }

    if (verdict.source === 'TRANCO_ANCHOR' || (verdict.severity === 'SAFE' && verdict.category === 'LEGITIMATE')) {
      return {
        bg: 'bg-emerald-950/60 text-emerald-400 border-emerald-500/40',
        text: 'Verified Safe Domain',
        subtext: 'High-Trust Global Anchor',
        icon: <ShieldCheck className="w-4 h-4 text-emerald-400" />,
      };
    }

    if (verdict.category === 'ANALYSIS_UNAVAILABLE') {
      return {
        bg: 'bg-amber-950/40 text-amber-300 border-amber-700/50',
        text: 'Analysis Unavailable',
        subtext: 'Threat intelligence gateway unreachable',
        icon: <HelpCircle className="w-4 h-4 text-amber-400" />,
      };
    }

    if (verdict.category === 'UNVERIFIED') {
      return {
        bg: 'bg-slate-800 text-slate-300 border-slate-700',
        text: 'Unverified Destination',
        subtext: 'Insufficient intelligence records',
        icon: <HelpCircle className="w-4 h-4 text-slate-400" />,
      };
    }

    if (verdict.category === 'NO_KNOWN_THREAT') {
      return {
        bg: 'bg-emerald-950/40 text-emerald-300 border-emerald-700/50',
        text: 'No Known Threat',
        subtext: 'Clean on available checks',
        icon: <ShieldCheck className="w-4 h-4 text-emerald-400" />,
      };
    }

    switch (verdict.severity) {
      case 'SAFE':
        return {
          bg: 'bg-threat-safeBg text-threat-safe border-emerald-500/30',
          text: t.statusProtected,
          subtext: 'Clean on available signals',
          icon: <ShieldCheck className="w-4 h-4 text-threat-safe" />,
        };
      case 'SUSPICIOUS':
        return {
          bg: 'bg-threat-warningBg text-threat-warning border-amber-500/30',
          text: t.statusSuspicious,
          subtext: 'Risk anomalies detected',
          icon: <AlertTriangle className="w-4 h-4 text-threat-warning" />,
        };
      case 'HIGH':
      case 'CRITICAL':
        return {
          bg: 'bg-threat-dangerBg text-threat-danger border-red-500/30',
          text: verdict.category === 'MALWARE' ? 'Malware Detected' : t.statusDangerous,
          subtext: 'Confirmed malicious threat',
          icon: <ShieldAlert className="w-4 h-4 text-threat-danger" />,
        };
      default:
        return {
          bg: 'bg-threat-neutralBg text-slate-300 border-slate-700',
          text: 'Unverified Website',
          subtext: 'Inconclusive threat intelligence',
          icon: <Info className="w-4 h-4 text-slate-400" />,
        };
    }
  };

  const badge = getBadgeConfig();
  const formattedTime = verdict.evaluatedAt
    ? new Date(verdict.evaluatedAt).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })
    : 'Just now';

  return (
    <div className="p-4 space-y-3">
      {/* Current Domain Box */}
      <div className="bg-shield-card border border-shield-border rounded-xl p-3 space-y-2.5 shadow-sm">
        <div className="flex items-center justify-between">
          <div className="flex items-center space-x-1.5 overflow-hidden">
            <Globe className="w-4 h-4 text-slate-400 shrink-0" />
            <span
              className="font-mono text-xs font-semibold text-white truncate max-w-[210px]"
              title={verdict.domain || verdict.canonicalUrl}
            >
              {verdict.domain || 'No active website'}
            </span>
          </div>

          <div className="flex items-center space-x-1.5 text-[10px]">
            {isHttps ? (
              <span className="flex items-center text-emerald-400 space-x-0.5 bg-emerald-950/40 px-1.5 py-0.5 rounded border border-emerald-800/40" title="Secure TLS connection">
                <Lock className="w-2.5 h-2.5" />
                <span>TLS</span>
              </span>
            ) : (
              <span className="flex items-center text-amber-400 space-x-0.5 bg-amber-950/40 px-1.5 py-0.5 rounded border border-amber-800/40" title="Insecure HTTP">
                <Unlock className="w-2.5 h-2.5" />
                <span>HTTP</span>
              </span>
            )}
          </div>
        </div>

        {/* Status Pill */}
        <div className={`flex items-center justify-between px-2.5 py-2 rounded-lg border text-xs font-semibold ${badge.bg}`}>
          <div className="flex items-center space-x-2">
            {badge.icon}
            <div>
              <span className="block leading-tight">{badge.text}</span>
              <span className="text-[10px] opacity-80 font-normal">{badge.subtext}</span>
            </div>
          </div>
          {verdict.category && (
            <span className="text-[9px] uppercase font-mono px-1.5 py-0.5 rounded bg-black/40 border border-white/10 shrink-0 ml-2">
              {verdict.category}
            </span>
          )}
        </div>

        {/* Scan Observability Banner: Live Scan vs Cache + Latency */}
        <div className="flex items-center justify-between pt-0.5 text-[10px] text-slate-400 font-mono border-t border-shield-border/40">
          <div className="flex items-center space-x-1">
            {verdict.isFreshScan ? (
              <span className="flex items-center space-x-1 text-cyan-400 font-semibold">
                <Zap className="w-3 h-3 text-cyan-400" />
                <span>Live Scan ({verdict.scanDurationMs || 0}ms)</span>
              </span>
            ) : (
              <span className="flex items-center space-x-1 text-slate-400">
                <Clock className="w-3 h-3" />
                <span>Cached Result</span>
              </span>
            )}
          </div>
          <div className="flex items-center space-x-2">
            <span>{formattedTime}</span>
            {onScanAgain && (
              <button
                type="button"
                onClick={onScanAgain}
                disabled={isScanning}
                className="text-cyan-400 hover:text-cyan-300 underline font-sans text-[10px]"
                title="Force fresh scan now"
              >
                Scan Again
              </button>
            )}
          </div>
        </div>

        {/* Active Scan Progress / Error Toasts */}
        {isScanning && (
          <div className="p-2 bg-indigo-950/50 border border-indigo-800/60 rounded-lg text-indigo-300 text-[11px] flex items-center space-x-2 animate-pulse">
            <div className="w-3 h-3 border-2 border-indigo-400 border-t-transparent rounded-full animate-spin shrink-0" />
            <span className="truncate">{scanMessage || 'Scanning website security pipeline...'}</span>
          </div>
        )}

        {scanError && (
          <div className="p-2 bg-red-950/60 border border-red-800/60 rounded-lg text-red-300 text-[11px] flex items-center space-x-1.5">
            <XCircle className="w-3.5 h-3.5 shrink-0 text-red-400" />
            <span>{scanError}</span>
          </div>
        )}
      </div>

      {/* Risk Assessment & Confidence Meter */}
      <div className="bg-shield-card border border-shield-border rounded-xl p-3 space-y-2">
        <div className="flex justify-between items-center text-xs">
          <div className="flex items-center space-x-1.5">
            <span className="text-slate-400 font-medium">{t.riskScore}</span>
            {verdict.confidence && (
              <span className="text-[10px] px-1.5 py-0.5 rounded bg-slate-800 text-slate-300 border border-shield-border/50 font-mono">
                {verdict.confidence} Confidence
              </span>
            )}
          </div>
          <span className="font-mono font-bold text-white text-sm">
            {Math.round(verdict.riskScore * 100)}%
          </span>
        </div>

        {/* Risk Meter Bar */}
        <div className="w-full bg-shield-dark rounded-full h-2 overflow-hidden border border-shield-border/60">
          <div
            className={`h-full transition-all duration-500 rounded-full ${
              verdict.riskScore > 0.7
                ? 'bg-threat-danger'
                : verdict.riskScore > 0.3
                ? 'bg-threat-warning'
                : 'bg-threat-safe'
            }`}
            style={{ width: `${Math.max(verdict.riskScore * 100, 3)}%` }}
          />
        </div>

        {/* Completed Security Checks Checklist */}
        {verdict.checksSummary && verdict.checksSummary.length > 0 && (
          <div className="pt-1 border-t border-shield-border/50">
            <button
              type="button"
              onClick={() => setShowChecks(!showChecks)}
              className="flex items-center justify-between w-full text-[11px] font-semibold text-slate-300 hover:text-white"
            >
              <span>Security Checks Completed ({verdict.checksSummary.filter((c) => c.status === 'completed').length}/{verdict.checksSummary.length})</span>
              {showChecks ? <ChevronUp className="w-3.5 h-3.5" /> : <ChevronDown className="w-3.5 h-3.5" />}
            </button>

            {showChecks && (
              <div className="mt-2 space-y-1 text-[10px] animate-fade-in">
                {verdict.checksSummary.map((chk, i) => (
                  <div
                    key={i}
                    className="p-1.5 bg-shield-dark/80 rounded-lg border border-shield-border/40 flex items-start space-x-2"
                  >
                    {chk.result === 'PASS' || chk.result === 'CLEAN' ? (
                      <CheckCircle2 className="w-3 h-3 text-emerald-400 shrink-0 mt-0.5" />
                    ) : chk.result === 'WARN' ? (
                      <AlertTriangle className="w-3 h-3 text-amber-400 shrink-0 mt-0.5" />
                    ) : chk.result === 'FAIL' ? (
                      <XCircle className="w-3 h-3 text-red-400 shrink-0 mt-0.5" />
                    ) : chk.result === 'UNAVAILABLE' ? (
                      <HelpCircle className="w-3 h-3 text-amber-400 shrink-0 mt-0.5" />
                    ) : (
                      <HelpCircle className="w-3 h-3 text-slate-500 shrink-0 mt-0.5" />
                    )}
                    <div className="flex-1 overflow-hidden">
                      <div className="flex items-center justify-between">
                        <div className="flex items-center space-x-1.5 truncate">
                          <span className="font-semibold text-slate-200">{chk.label}</span>
                          {chk.inputType && (
                            <span className="text-[8px] font-mono px-1 py-0.2 bg-slate-800 text-slate-400 rounded">
                              {chk.inputType}
                            </span>
                          )}
                        </div>
                        <span
                          className={`font-mono uppercase text-[9px] shrink-0 ml-1.5 ${
                            chk.result === 'PASS' || chk.result === 'CLEAN'
                              ? 'text-emerald-400'
                              : chk.result === 'WARN'
                              ? 'text-amber-400'
                              : chk.result === 'FAIL'
                              ? 'text-red-400'
                              : chk.result === 'UNAVAILABLE'
                              ? 'text-amber-400'
                              : 'text-slate-400'
                          }`}
                        >
                          {chk.result}
                        </span>
                      </div>
                      <p className="text-slate-400 truncate">{chk.details}</p>
                      {chk.error && (
                        <p className="text-red-400 text-[9px] truncate">Error: {chk.error}</p>
                      )}
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}

        {/* Evidence Findings List */}
        <div className="pt-1 space-y-1">
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
