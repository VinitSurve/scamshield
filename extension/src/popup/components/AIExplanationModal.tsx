import React, { useState } from 'react';
import {
  FileText,
  X,
  CheckCircle2,
  Cpu,
  ShieldAlert,
} from 'lucide-react';
import { UrlEvidenceExplanation } from '../../ai/types';
import { SafeMessaging } from '../../security/safe-messaging';

interface AIExplanationModalProps {
  isOpen: boolean;
  onClose: () => void;
  url: string;
  domain: string;
  severity: string;
  riskScore: number;
  evidence: string[];
  redirectHops?: number;
  domIndicators?: string[];
  userLanguage?: 'en' | 'hi' | 'mr';
}

export const AIExplanationModal: React.FC<AIExplanationModalProps> = ({
  isOpen,
  onClose,
  url,
  domain,
  severity,
  riskScore,
  evidence,
  redirectHops,
  domIndicators,
  userLanguage = 'en',
}) => {
  const [isExplaining, setIsExplaining] = useState(false);
  const [explanation, setExplanation] = useState<UrlEvidenceExplanation | null>(null);

  if (!isOpen) return null;

  const handleFetchExplanation = async () => {
    setIsExplaining(true);
    setExplanation(null);

    try {
      const res = await SafeMessaging.sendToBackground<UrlEvidenceExplanation>(
        'AI_EXPLAIN_URL_THREAT',
        {
          url,
          domain,
          verdictSeverity: severity,
          riskScore,
          evidence,
          redirectHops,
          domIndicators,
          userLanguage,
        },
        20000
      );
      setExplanation(res);
    } catch (err: any) {
      setExplanation({
        success: false,
        summary: err.message || 'Security threat explanation could not be retrieved.',
        dangerLevel: 'HIGH',
        tacticsDetected: ['Scanner Detection'],
        safetyGuidance: ['Leave the suspicious page immediately.'],
      });
    } finally {
      setIsExplaining(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-3 bg-slate-950/85 backdrop-blur-sm animate-fade-in">
      <div className="bg-shield-card border border-shield-border rounded-2xl w-full max-w-sm max-h-[90vh] flex flex-col shadow-2xl overflow-hidden text-xs">
        {/* Header */}
        <div className="flex items-center justify-between p-3.5 border-b border-shield-border bg-shield-dark">
          <div className="flex items-center space-x-2">
            <div className="p-1.5 bg-shield-accent/15 border border-shield-accent/30 rounded-lg text-shield-accent">
              <ShieldAlert className="w-4 h-4" />
            </div>
            <div>
              <h3 className="font-bold text-white uppercase tracking-wider text-[11px]">
                Security Threat Assessment
              </h3>
              <p className="text-[10px] text-slate-400 font-mono truncate max-w-[200px]">
                {domain}
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="text-slate-400 hover:text-white p-1 rounded-lg transition-colors"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Content */}
        <div className="p-3.5 space-y-3 overflow-y-auto flex-1">
          {/* Target Domain Overview */}
          <div className="p-2.5 bg-shield-dark rounded-xl border border-shield-border space-y-1">
            <div className="flex items-center justify-between text-[11px]">
              <span className="text-slate-400">Verdict Severity:</span>
              <span
                className={`font-bold uppercase ${
                  severity === 'CRITICAL' || severity === 'HIGH'
                    ? 'text-red-400'
                    : severity === 'SUSPICIOUS' || severity === 'MEDIUM'
                    ? 'text-amber-400'
                    : 'text-emerald-400'
                }`}
              >
                {severity} ({riskScore}/100)
              </span>
            </div>
            <div className="text-[10px] text-slate-400 truncate font-mono">
              {url}
            </div>
          </div>

          {!explanation && !isExplaining && (
            <div className="text-center py-4 space-y-3">
              <p className="text-slate-300 text-xs">
                Request a comprehensive security breakdown of why this page was flagged by ScamShield's
                deterministic threat scanner.
              </p>
              <button
                onClick={handleFetchExplanation}
                className="px-4 py-2 bg-shield-accent hover:bg-shield-accentHover text-slate-950 font-bold rounded-xl text-xs flex items-center justify-center space-x-1.5 mx-auto shadow-md transition-all active:scale-[0.98]"
              >
                <FileText className="w-3.5 h-3.5" />
                <span>Explain Threat Findings</span>
              </button>
            </div>
          )}

          {isExplaining && (
            <div className="text-center py-6 space-y-2">
              <div className="w-5 h-5 border-2 border-shield-accent border-t-transparent rounded-full animate-spin mx-auto" />
              <p className="text-slate-400 text-xs font-mono">
                Aggregating threat intelligence reasoning...
              </p>
            </div>
          )}

          {explanation && (
            <div className="space-y-3 animate-fade-in">
              <div className="p-3 bg-shield-dark rounded-xl border border-shield-border space-y-2">
                <div className="flex items-center justify-between border-b border-shield-border/50 pb-1.5">
                  <span className="text-[10px] font-bold text-slate-300 uppercase tracking-wider">
                    Executive Threat Summary
                  </span>
                  {explanation.providerUsed && (
                    <span className="text-[9px] font-mono text-shield-accent flex items-center space-x-1">
                      <Cpu className="w-3 h-3" />
                      <span>{explanation.providerUsed.toUpperCase()}</span>
                    </span>
                  )}
                </div>
                <p className="text-slate-200 text-xs leading-relaxed font-medium">
                  {explanation.summary}
                </p>
              </div>

              {explanation.tacticsDetected?.length > 0 && (
                <div className="space-y-1">
                  <span className="text-[11px] font-semibold text-slate-300 block">
                    Deceptive Tactics Identified:
                  </span>
                  <div className="flex flex-wrap gap-1">
                    {explanation.tacticsDetected.map((tactic, i) => (
                      <span
                        key={i}
                        className="px-2 py-0.5 bg-red-950/60 border border-red-800/40 text-red-300 rounded text-[10px] font-medium"
                      >
                        ⚠ {tactic}
                      </span>
                    ))}
                  </div>
                </div>
              )}

              {explanation.safetyGuidance?.length > 0 && (
                <div className="space-y-1.5 pt-1">
                  <span className="text-[11px] font-semibold text-slate-300 block">
                    Recommended Protection Steps:
                  </span>
                  <ul className="space-y-1 text-slate-300 text-[11px]">
                    {explanation.safetyGuidance.map((step, i) => (
                      <li key={i} className="flex items-start space-x-1.5">
                        <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400 shrink-0 mt-0.5" />
                        <span>{step}</span>
                      </li>
                    ))}
                  </ul>
                </div>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
