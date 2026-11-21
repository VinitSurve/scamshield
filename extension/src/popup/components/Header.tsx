import React from 'react';
import { Shield, ShieldCheck, ShieldAlert, Settings } from 'lucide-react';
import { ThreatSeverity } from '../../types/threat';

interface HeaderProps {
  severity: ThreatSeverity;
  protectionActive: boolean;
  onOpenSettings: () => void;
  title: string;
  tagline: string;
}

export const Header: React.FC<HeaderProps> = ({
  severity,
  protectionActive,
  onOpenSettings,
  title,
  tagline,
}) => {
  const getStatusIcon = () => {
    if (!protectionActive) {
      return <Shield className="w-5 h-5 text-slate-400" />;
    }
    switch (severity) {
      case 'SAFE':
        return <ShieldCheck className="w-5 h-5 text-threat-safe" />;
      case 'SUSPICIOUS':
        return <ShieldAlert className="w-5 h-5 text-threat-warning" />;
      case 'HIGH':
      case 'CRITICAL':
        return <ShieldAlert className="w-5 h-5 text-threat-danger animate-pulse" />;
      default:
        return <Shield className="w-5 h-5 text-shield-accent" />;
    }
  };

  return (
    <header className="flex items-center justify-between px-4 py-3 bg-shield-card border-b border-shield-border">
      <div className="flex items-center space-x-2.5">
        <div className="p-1.5 rounded-lg bg-shield-dark/80 border border-shield-border">
          {getStatusIcon()}
        </div>
        <div>
          <div className="flex items-center space-x-1.5">
            <span className="font-bold text-sm tracking-wide text-white">{title}</span>
            <span className="text-[10px] px-1.5 py-0.2 bg-shield-accent/20 text-shield-accent rounded border border-shield-accent/30 font-mono">
              MVP
            </span>
          </div>
          <p className="text-[11px] text-slate-400 font-medium">{tagline}</p>
        </div>
      </div>

      <button
        onClick={onOpenSettings}
        className="p-1.5 rounded-md text-slate-400 hover:text-white hover:bg-shield-cardHover transition-colors"
        title="Settings"
      >
        <Settings className="w-4 h-4" />
      </button>
    </header>
  );
};
