import React, { useState } from 'react';
import {
  Sparkles,
  X,
  CheckCircle2,
  Send,
  ChevronDown,
  ChevronUp,
  Cpu,
} from 'lucide-react';
import { StructuredScamAnalysis } from '../../ai/types';
import { SafeMessaging } from '../../security/safe-messaging';
import { LocalMessageHeuristics } from '../../security/local-message-heuristics';

interface AIScamAnalyzerModalProps {
  isOpen: boolean;
  onClose: () => void;
  userLanguage?: 'en' | 'hi' | 'mr';
}

export const AIScamAnalyzerModal: React.FC<AIScamAnalyzerModalProps> = ({
  isOpen,
  onClose,
  userLanguage = 'en',
}) => {
  const [inputText, setInputText] = useState('');
  const [sourceType, setSourceType] = useState<'SMS' | 'WHATSAPP' | 'EMAIL' | 'OTHER'>('WHATSAPP');
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [result, setResult] = useState<StructuredScamAnalysis | null>(null);
  const [showIndicators, setShowIndicators] = useState(false);
  const [showDiagnostics, setShowDiagnostics] = useState(false);

  if (!isOpen) return null;

  const handleAnalyze = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!inputText.trim()) return;

    setIsAnalyzing(true);
    setResult(null);

    try {
      const res = await SafeMessaging.sendToBackground<StructuredScamAnalysis>(
        'AI_ANALYZE_MESSAGE',
        {
          messageText: inputText,
          sourceType,
          userLanguage,
        },
        25000 // 25s timeout for AI analysis
      );
      setResult(res);
    } catch (err: any) {
      const fallbackResult = LocalMessageHeuristics.analyze(inputText, sourceType, {
        requestId: `ui_${Date.now()}`,
        timestamp: new Date().toISOString(),
        backendReachable: false,
        errorType: err.message || 'Messaging channel failed',
        finalAnalysisStatus: 'LOCAL_HEURISTIC_FALLBACK',
      });
      setResult(fallbackResult);
    } finally {
      setIsAnalyzing(false);
    }
  };

  const sampleScams = [
    {
      label: 'SBI KYC Scam (SMS)',
      text: 'Dear SBI User, your YONO account is suspended today due to pending KYC update. Click http://sbi-kyc-update.top to verify your Pan Card or your account will be blocked within 24 hours.',
    },
    {
      label: 'Electricity Bill Scam (WhatsApp)',
      text: 'Dear consumer your electricity power will be disconnected tonight at 9:30 pm from electricity office because your previous month bill was not updated. Please immediately contact our officer at 9876543210.',
    },
    {
      label: 'UPI Cashback Scam (SMS)',
      text: 'Congratulations! You have received a cashback reward of Rs 4,999 on PhonePe. Click here to claim your money directly to bank: https://phonepe-rewards.example/claim',
    },
  ];

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-3 bg-slate-950/80 backdrop-blur-sm animate-fade-in">
      <div className="bg-shield-card border border-shield-border rounded-2xl w-full max-w-sm max-h-[92vh] flex flex-col shadow-2xl overflow-hidden">
        {/* Header */}
        <div className="flex items-center justify-between p-3.5 border-b border-shield-border bg-shield-dark">
          <div className="flex items-center space-x-2">
            <div className="p-1.5 bg-indigo-500/20 border border-indigo-500/30 rounded-lg text-indigo-400">
              <Sparkles className="w-4 h-4" />
            </div>
            <div>
              <h3 className="text-xs font-bold text-white uppercase tracking-wider">
                ScamShield AI Analyzer
              </h3>
              <p className="text-[10px] text-slate-400">Powered by Gemini & Groq</p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="text-slate-400 hover:text-white p-1 rounded-lg transition-colors"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Scrollable Content */}
        <div className="p-3.5 space-y-3.5 overflow-y-auto flex-1 text-xs">
          {/* Input Form */}
          <form onSubmit={handleAnalyze} className="space-y-2.5">
            <div className="flex items-center justify-between">
              <label className="text-[11px] font-semibold text-slate-300">Message Source</label>
              <div className="flex space-x-1">
                {(['WHATSAPP', 'SMS', 'EMAIL', 'OTHER'] as const).map((s) => (
                  <button
                    key={s}
                    type="button"
                    onClick={() => setSourceType(s)}
                    className={`px-2 py-0.5 rounded text-[10px] font-medium border ${
                      sourceType === s
                        ? 'bg-indigo-600 border-indigo-500 text-white'
                        : 'bg-shield-dark border-shield-border text-slate-400 hover:text-white'
                    }`}
                  >
                    {s}
                  </button>
                ))}
              </div>
            </div>

            <div>
              <textarea
                rows={3}
                placeholder="Paste suspicious SMS, WhatsApp message, or email text here..."
                value={inputText}
                onChange={(e) => setInputText(e.target.value)}
                className="w-full bg-shield-dark border border-shield-border rounded-xl p-2.5 text-xs text-white placeholder:text-slate-500 focus:outline-none focus:border-indigo-500 resize-none font-sans"
              />
            </div>

            {/* Quick Samples */}
            <div className="flex items-center space-x-1.5 overflow-x-auto pb-1 text-[10px]">
              <span className="text-slate-500 shrink-0">Try:</span>
              {sampleScams.map((s, idx) => (
                <button
                  key={idx}
                  type="button"
                  onClick={() => setInputText(s.text)}
                  className="px-2 py-0.5 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded border border-shield-border/60 shrink-0"
                >
                  {s.label}
                </button>
              ))}
            </div>

            <button
              type="submit"
              disabled={isAnalyzing || !inputText.trim()}
              className="w-full py-2 bg-gradient-to-r from-indigo-600 to-purple-600 hover:from-indigo-500 hover:to-purple-500 disabled:opacity-50 text-white font-bold rounded-xl text-xs flex items-center justify-center space-x-1.5 shadow-md transition-all active:scale-[0.99]"
            >
              {isAnalyzing ? (
                <>
                  <Sparkles className="w-3.5 h-3.5 animate-spin" />
                  <span>Evaluating Threat Intelligence...</span>
                </>
              ) : (
                <>
                  <Send className="w-3.5 h-3.5" />
                  <span>Analyze Message with AI</span>
                </>
              )}
            </button>
          </form>

          {/* Results Display */}
          {result && (
            <div className="p-3 bg-shield-dark border border-shield-border rounded-xl space-y-2.5 animate-fade-in">
              {/* Dual Engine Status Badges */}
              <div className="flex items-center justify-between pb-1 text-[10px]">
                <div className="flex items-center space-x-1.5">
                  <span className="text-slate-400">AI Engine:</span>
                  <span
                    className={`px-1.5 py-0.2 rounded font-mono font-semibold ${
                      result.aiStatus === 'SUCCESS' || (!result.isLocalHeuristicFallback && result.success)
                        ? 'bg-emerald-950/80 text-emerald-400 border border-emerald-800/40'
                        : 'bg-amber-950/80 text-amber-400 border border-amber-800/40'
                    }`}
                  >
                    {result.aiStatus === 'SUCCESS' || (!result.isLocalHeuristicFallback && result.success)
                      ? `LIVE (${(result.providerUsed || 'AI').toUpperCase()})`
                      : 'FAILED'}
                  </span>
                </div>

                <div className="flex items-center space-x-1.5">
                  <span className="text-slate-400">Security Engine:</span>
                  <span
                    className={`px-1.5 py-0.2 rounded font-mono font-semibold ${
                      result.securityStatus === 'SUCCESS' || result.success
                        ? 'bg-emerald-950/80 text-emerald-400 border border-emerald-800/40'
                        : 'bg-red-950/80 text-red-400 border border-red-800/40'
                    }`}
                  >
                    {result.isLocalHeuristicFallback ? 'HEURISTIC FALLBACK' : 'ACTIVE'}
                  </span>
                </div>
              </div>

              {/* Local Heuristic Fallback Warning Alert */}
              {result.isLocalHeuristicFallback && (
                <div className="p-2.5 bg-amber-950/30 border border-amber-600/40 rounded-lg text-[11px] space-y-1">
                  <div className="flex items-center space-x-1.5 text-amber-400 font-bold">
                    <span>⚠️ AI ANALYSIS UNAVAILABLE</span>
                  </div>
                  <p className="text-amber-200/90 leading-tight text-[10px]">
                    All configured AI provider requests failed or were unreachable. However, ScamShield local security checks analyzed the message directly using deterministic threat signatures.
                  </p>
                </div>
              )}

              {/* Verdict Header */}
              <div className="flex items-center justify-between border-b border-shield-border/60 pb-2">
                <div className="flex items-center space-x-2">
                  <span
                    className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase ${
                      result.classification === 'SCAM' || result.classification === 'MALICIOUS'
                        ? 'bg-red-950 border border-red-700 text-red-300'
                        : result.classification === 'SUSPICIOUS'
                        ? 'bg-amber-950 border border-amber-700 text-amber-300'
                        : result.classification === 'SAFE'
                        ? 'bg-emerald-950 border border-emerald-700 text-emerald-300'
                        : 'bg-slate-800 text-slate-400'
                    }`}
                  >
                    {result.classification}
                  </span>
                  <span className="text-[10px] text-slate-400 font-mono">
                    Score: {Math.round(result.confidenceScore * 100)}%
                  </span>
                </div>

                <div className="flex items-center space-x-1.5 text-[10px] text-slate-400 font-mono">
                  <Cpu className="w-3 h-3 text-indigo-400" />
                  <span>
                    {result.isLocalHeuristicFallback
                      ? 'LOCAL HEURISTICS'
                      : result.providerUsed?.toUpperCase() || 'AI'}
                  </span>
                  <span>({result.latencyMs}ms)</span>
                </div>
              </div>

              {/* Summary */}
              <div>
                <p className="text-xs text-white leading-relaxed font-medium whitespace-pre-line">
                  {result.summary}
                </p>
              </div>

              {/* Category & Tactics */}
              <div className="space-y-1">
                <div className="flex items-center justify-between text-[11px]">
                  <span className="text-slate-400">Scam Category:</span>
                  <span className="text-white font-mono font-semibold">{result.scamCategory}</span>
                </div>

                {result.socialEngineeringTactics?.length > 0 && (
                  <div className="flex flex-wrap gap-1 pt-1">
                    {result.socialEngineeringTactics.map((tactic, i) => (
                      <span
                        key={i}
                        className="px-1.5 py-0.5 bg-indigo-950/60 border border-indigo-800/40 text-indigo-300 rounded text-[9px]"
                      >
                        {tactic}
                      </span>
                    ))}
                  </div>
                )}
              </div>

              {/* Extracted Entities */}
              {(result.extractedEntities?.brandImpersonated ||
                result.extractedEntities?.suspiciousUrls?.length) && (
                <div className="p-2 bg-slate-900/80 rounded-lg border border-shield-border/50 text-[11px] space-y-1">
                  {result.extractedEntities.brandImpersonated && (
                    <div className="flex items-center justify-between">
                      <span className="text-slate-400">Impersonated Brand:</span>
                      <span className="text-red-400 font-bold">
                        {result.extractedEntities.brandImpersonated}
                      </span>
                    </div>
                  )}
                  {result.extractedEntities.suspiciousUrls?.map((u, i) => (
                    <div key={i} className="text-red-300 font-mono truncate text-[10px]">
                      ⚠ {u}
                    </div>
                  ))}
                </div>
              )}

              {/* Recommended Actions */}
              {result.recommendedActions?.length > 0 && (
                <div className="space-y-1 pt-1">
                  <span className="text-[11px] font-semibold text-slate-300 block">
                    Recommended Actions:
                  </span>
                  <ul className="space-y-1 text-[11px] text-slate-300">
                    {result.recommendedActions.map((action, i) => (
                      <li key={i} className="flex items-start space-x-1.5">
                        <CheckCircle2 className="w-3 h-3 text-emerald-400 shrink-0 mt-0.5" />
                        <span>{action}</span>
                      </li>
                    ))}
                  </ul>
                </div>
              )}

              {/* Expandable Indicators */}
              {result.indicators?.length > 0 && (
                <div className="pt-1">
                  <button
                    type="button"
                    onClick={() => setShowIndicators(!showIndicators)}
                    className="flex items-center justify-between w-full text-[10px] text-slate-400 hover:text-white"
                  >
                    <span>Technical Indicators ({result.indicators.length})</span>
                    {showIndicators ? <ChevronUp className="w-3 h-3" /> : <ChevronDown className="w-3 h-3" />}
                  </button>

                  {showIndicators && (
                    <div className="mt-1.5 space-y-1 text-[10px]">
                      {result.indicators.map((ind, i) => (
                        <div
                          key={i}
                          className="p-1.5 bg-slate-900 rounded border border-shield-border/40 space-y-0.5"
                        >
                          <div className="flex items-center justify-between text-slate-300 font-semibold">
                            <span>{ind.type}</span>
                            <span className="text-amber-400 font-mono text-[9px]">
                              {ind.severity}
                            </span>
                          </div>
                          <p className="text-slate-400">{ind.description}</p>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              )}

              {/* Collapsible Developer Diagnostics & Telemetry Panel (Priority 2) */}
              {result.diagnostics && (
                <div className="pt-2 border-t border-shield-border/50">
                  <button
                    type="button"
                    onClick={() => setShowDiagnostics(!showDiagnostics)}
                    className="flex items-center justify-between w-full text-[10px] text-indigo-400 hover:text-indigo-300 font-mono"
                  >
                    <span>🛠 Developer Diagnostics & Engine Telemetry</span>
                    {showDiagnostics ? <ChevronUp className="w-3 h-3" /> : <ChevronDown className="w-3 h-3" />}
                  </button>

                  {showDiagnostics && (
                    <div className="mt-2 p-2 bg-slate-950 rounded-lg border border-indigo-900/40 text-[9px] font-mono text-slate-300 space-y-1.5">
                      <div className="grid grid-cols-2 gap-1 pb-1 border-b border-slate-800">
                        <div>
                          <span className="text-slate-500 block">Request ID:</span>
                          <span className="text-white truncate block">{result.diagnostics.requestId}</span>
                        </div>
                        <div>
                          <span className="text-slate-500 block">Backend Reachable:</span>
                          <span className={result.diagnostics.backendReachable ? 'text-emerald-400' : 'text-amber-400'}>
                            {result.diagnostics.backendReachable ? 'YES (Port 3001)' : 'NO (Offline)'}
                          </span>
                        </div>
                      </div>

                      <div className="grid grid-cols-2 gap-1 pb-1 border-b border-slate-800">
                        <div>
                          <span className="text-slate-500 block">Provider Attempted:</span>
                          <span className="text-white">{result.diagnostics.providerAttempted || result.providerUsed || 'None'}</span>
                        </div>
                        <div>
                          <span className="text-slate-500 block">Model:</span>
                          <span className="text-indigo-300">{result.diagnostics.model || result.modelUsed || 'N/A'}</span>
                        </div>
                      </div>

                      <div className="grid grid-cols-2 gap-1 pb-1 border-b border-slate-800">
                        <div>
                          <span className="text-slate-500 block">Fallback Attempted:</span>
                          <span className="text-white">{result.diagnostics.fallbackAttempted ? 'YES' : 'NO'}</span>
                        </div>
                        <div>
                          <span className="text-slate-500 block">Fallback Result:</span>
                          <span className={result.diagnostics.fallbackResult === 'SUCCESS' ? 'text-emerald-400' : 'text-amber-400'}>
                            {result.diagnostics.fallbackResult || 'N/A'}
                          </span>
                        </div>
                      </div>

                      <div>
                        <span className="text-slate-500 block">Final Status:</span>
                        <span className="text-emerald-400 font-bold">{result.diagnostics.finalAnalysisStatus}</span>
                      </div>

                      {result.diagnostics.providerDiagnostics && result.diagnostics.providerDiagnostics.length > 0 && (
                        <div className="pt-1">
                          <span className="text-slate-400 font-bold block mb-1">Provider Trace:</span>
                          {result.diagnostics.providerDiagnostics.map((pd, idx) => (
                            <div key={idx} className="p-1 bg-slate-900 rounded mb-1 text-[8.5px]">
                              <div className="flex justify-between">
                                <span className="font-bold text-slate-300">{pd.provider.toUpperCase()} ({pd.model})</span>
                                <span className={pd.status === 'SUCCESS' ? 'text-emerald-400' : 'text-red-400'}>
                                  {pd.status} {pd.httpStatus ? `[HTTP ${pd.httpStatus}]` : ''}
                                </span>
                              </div>
                              {pd.error && <p className="text-red-300 mt-0.5 truncate">{pd.error}</p>}
                            </div>
                          ))}
                        </div>
                      )}
                    </div>
                  )}
                </div>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
