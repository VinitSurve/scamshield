import React, { useState } from 'react';
import { ShieldAlert, ArrowLeft, AlertTriangle, ChevronRight } from 'lucide-react';
import { SafeMessaging } from '../security/safe-messaging';

export const InterstitialApp: React.FC = () => {
  const urlParams = new URLSearchParams(window.location.search);
  const targetUrl = urlParams.get('url') || 'https://unknown-target.example';
  const targetDomain = urlParams.get('domain') || new URL(targetUrl).hostname;
  const category = urlParams.get('category') || 'PHISHING';

  const [showOverride, setShowOverride] = useState(false);
  const [isBypassing, setIsBypassing] = useState(false);

  const handleBackToSafety = () => {
    if (window.history.length > 1) {
      window.history.back();
    } else {
      window.location.href = 'chrome://newtab';
    }
  };

  const handleProceedAnyway = async () => {
    setIsBypassing(true);
    try {
      await SafeMessaging.sendToBackground('OVERRIDE_THREAT_BLOCK', {
        domain: targetDomain,
        durationMinutes: 15,
      });
      // Navigate to the originally blocked URL
      window.location.href = targetUrl;
    } catch (err) {
      console.error('Failed to bypass block:', err);
      window.location.href = targetUrl;
    }
  };

  return (
    <div className="w-full max-w-xl mx-auto p-6 space-y-6">
      {/* Top Banner */}
      <div className="flex items-center space-x-3 text-red-500 bg-red-950/30 border border-red-800/40 p-4 rounded-2xl">
        <div className="p-3 bg-red-500/20 rounded-xl shrink-0">
          <ShieldAlert className="w-8 h-8 text-red-400" />
        </div>
        <div>
          <h1 className="text-lg font-bold text-white tracking-tight">
            ScamShield Protection Alert
          </h1>
          <p className="text-xs text-red-300">
            Deceptive or malicious website blocked for your safety.
          </p>
        </div>
      </div>

      {/* Main Threat Info Card */}
      <div className="bg-shield-card border border-shield-border rounded-2xl p-6 space-y-4 shadow-2xl">
        <div>
          <span className="text-[11px] font-mono uppercase tracking-wider text-slate-400 block mb-1">
            Blocked Destination
          </span>
          <div className="bg-shield-dark border border-shield-border rounded-xl p-3 font-mono text-xs text-red-400 break-all select-all">
            {targetUrl}
          </div>
        </div>

        <div className="space-y-2">
          <span className="text-xs font-semibold text-slate-300">
            Why was this website blocked?
          </span>
          <div className="space-y-2 text-xs text-slate-300 leading-relaxed">
            <div className="flex items-start space-x-2">
              <span className="text-red-400 font-bold shrink-0 mt-0.5">•</span>
              <span>
                <strong>Threat Category:</strong>{' '}
                <span className="font-mono text-amber-400 uppercase">{category}</span>
              </span>
            </div>
            <div className="flex items-start space-x-2">
              <span className="text-red-400 font-bold shrink-0 mt-0.5">•</span>
              <span>
                This domain has been identified as a credential-harvesting, fake KYC, or financial fraud gateway mimicking legitimate institutions.
              </span>
            </div>
            <div className="flex items-start space-x-2">
              <span className="text-red-400 font-bold shrink-0 mt-0.5">•</span>
              <span>
                Entering passwords, ATM PINs, OTPs, or UPI details on this site can result in immediate financial theft.
              </span>
            </div>
          </div>
        </div>

        {/* Primary Safe Action */}
        <div className="pt-2">
          <button
            onClick={handleBackToSafety}
            className="w-full py-3.5 px-4 bg-shield-accent hover:bg-shield-accentHover text-slate-950 font-bold rounded-xl text-sm flex items-center justify-center space-x-2 shadow-lg shadow-cyan-950/50 transition-all active:scale-[0.99]"
          >
            <ArrowLeft className="w-4 h-4" />
            <span>Return to Safety (Recommended)</span>
          </button>
        </div>

        {/* Deliberate Override Accordion */}
        <div className="border-t border-shield-border pt-3">
          <button
            onClick={() => setShowOverride(!showOverride)}
            className="flex items-center justify-between w-full text-xs text-slate-400 hover:text-slate-300 py-1 transition-colors"
          >
            <span>Advanced Options</span>
            <ChevronRight
              className={`w-4 h-4 transition-transform ${showOverride ? 'rotate-90' : ''}`}
            />
          </button>

          {showOverride && (
            <div className="mt-3 p-3 bg-red-950/20 border border-red-900/40 rounded-xl space-y-2 text-xs">
              <div className="flex items-center space-x-1.5 text-amber-400 font-semibold text-[11px]">
                <AlertTriangle className="w-3.5 h-3.5 shrink-0" />
                <span>Override Security Warning</span>
              </div>
              <p className="text-[11px] text-slate-300 leading-normal">
                If you proceed, ScamShield will temporarily pause blocking for this domain for 15 minutes. We strongly advise against entering any sensitive credentials or OTPs.
              </p>
              <button
                onClick={handleProceedAnyway}
                disabled={isBypassing}
                className="w-full py-2 bg-red-600/30 hover:bg-red-600/50 text-red-200 border border-red-500/50 rounded-lg text-xs font-semibold transition-colors"
              >
                {isBypassing ? 'Bypassing...' : 'Proceed to Unsafe Website Anyway'}
              </button>
            </div>
          )}
        </div>
      </div>

      <div className="text-center text-[11px] text-slate-500 font-mono">
        ScamShield Security Engine • Think Before You Click
      </div>
    </div>
  );
};
