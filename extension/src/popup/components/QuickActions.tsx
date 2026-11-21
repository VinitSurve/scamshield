import React from 'react';
import { RefreshCw, Flag, Shield, ShieldOff, FlaskConical } from 'lucide-react';

interface QuickActionsProps {
  onScan: () => void;
  onOpenReport: () => void;
  onToggleProtection: () => void;
  onOpenTestLab: () => void;
  isScanning: boolean;
  protectionActive: boolean;
  t: Record<string, string>;
}

export const QuickActions: React.FC<QuickActionsProps> = ({
  onScan,
  onOpenReport,
  onToggleProtection,
  onOpenTestLab,
  isScanning,
  protectionActive,
  t,
}) => {
  return (
    <div className="px-4 pb-4 space-y-2.5">
      <div className="grid grid-cols-2 gap-2">
        {/* Scan Website Button */}
        <button
          onClick={onScan}
          disabled={isScanning}
          className="flex items-center justify-center space-x-1.5 py-2.5 px-3 bg-shield-accent/15 hover:bg-shield-accent/25 text-shield-accent border border-shield-accent/30 rounded-xl text-xs font-semibold transition-all active:scale-[0.98] disabled:opacity-50"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${isScanning ? 'animate-spin' : ''}`} />
          <span>{isScanning ? t.scanning : t.scanSite}</span>
        </button>

        {/* Report Threat Button */}
        <button
          onClick={onOpenReport}
          className="flex items-center justify-center space-x-1.5 py-2.5 px-3 bg-shield-card hover:bg-shield-cardHover text-slate-200 border border-shield-border rounded-xl text-xs font-semibold transition-all active:scale-[0.98]"
        >
          <Flag className="w-3.5 h-3.5 text-amber-400" />
          <span>{t.reportThreat}</span>
        </button>
      </div>

      {/* Proactive Protection Toggle */}
      <button
        onClick={onToggleProtection}
        className={`w-full flex items-center justify-between py-2 px-3 rounded-xl border text-xs font-medium transition-all ${
          protectionActive
            ? 'bg-shield-card/60 text-slate-300 border-shield-border hover:bg-shield-cardHover'
            : 'bg-red-950/20 text-red-300 border-red-800/40 hover:bg-red-900/30'
        }`}
      >
        <div className="flex items-center space-x-2">
          {protectionActive ? (
            <Shield className="w-3.5 h-3.5 text-emerald-400" />
          ) : (
            <ShieldOff className="w-3.5 h-3.5 text-red-400" />
          )}
          <span>{protectionActive ? t.protectionActive : t.protectionPaused}</span>
        </div>
        <span className="text-[11px] underline text-slate-400">
          {protectionActive ? 'Pause' : 'Resume'}
        </span>
      </button>

      {/* Developer / Hackathon Security Test Lab Launcher */}
      <button
        onClick={onOpenTestLab}
        className="w-full flex items-center justify-center space-x-1.5 py-1.5 px-3 bg-shield-dark hover:bg-shield-cardHover text-cyan-400 border border-cyan-800/40 rounded-xl text-[11px] font-semibold transition-colors"
        title="Open Developer Security Test Lab"
      >
        <FlaskConical className="w-3.5 h-3.5" />
        <span>Security Test Lab [Dev Mode]</span>
      </button>
    </div>
  );
};
