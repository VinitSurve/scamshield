import React, { useState } from 'react';
import { X, Flag, CheckCircle, AlertCircle } from 'lucide-react';
import { SafeMessaging } from '../../security/safe-messaging';
import { CommunityReportPayload, CommunityReportResponse } from '../../types/messages';

interface ReportModalProps {
  isOpen: boolean;
  onClose: () => void;
  domain: string;
  url: string;
  t: Record<string, string>;
}

const THREAT_CATEGORIES = [
  { value: 'PHISHING', label: 'Phishing / Fake Login Page' },
  { value: 'FAKE_KYC', label: 'Fake Banking / KYC Update Scam' },
  { value: 'UPI_FRAUD', label: 'Fraudulent UPI / Payment Gateway' },
  { value: 'GOV_IMPERSONATION', label: 'Government / Police / Challan Scam' },
  { value: 'LOTTERY_SCAM', label: 'Lottery / Job / Task Fraud' },
  { value: 'MALWARE', label: 'Malware / Malicious APK Download' },
  { value: 'OTHER', label: 'Other Digital Fraud' },
];

export const ReportModal: React.FC<ReportModalProps> = ({
  isOpen,
  onClose,
  domain,
  url,
  t,
}) => {
  const [category, setCategory] = useState('PHISHING');
  const [description, setDescription] = useState('');
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [result, setResult] = useState<CommunityReportResponse | null>(null);
  const [error, setError] = useState<string | null>(null);

  if (!isOpen) return null;

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsSubmitting(true);
    setError(null);

    const payload: CommunityReportPayload = {
      domain,
      url,
      threatCategory: category,
      description,
      evidenceMetadata: {
        submittedFrom: 'extension_popup',
        timestamp: new Date().toISOString(),
      },
    };

    try {
      const response = await SafeMessaging.sendToBackground<CommunityReportResponse>(
        'SUBMIT_COMMUNITY_REPORT',
        payload
      );
      setResult(response);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to submit report');
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <div className="fixed inset-0 bg-black/70 backdrop-blur-sm flex items-center justify-center p-3 z-50">
      <div className="bg-shield-card border border-shield-border rounded-xl w-full max-w-sm p-4 space-y-3.5 shadow-xl">
        <div className="flex items-center justify-between border-b border-shield-border pb-2.5">
          <div className="flex items-center space-x-2">
            <Flag className="w-4 h-4 text-amber-400" />
            <h3 className="text-xs font-bold text-white uppercase tracking-wider">
              {t.reportModalTitle}
            </h3>
          </div>
          <button
            onClick={onClose}
            className="text-slate-400 hover:text-white p-1 rounded-md hover:bg-shield-cardHover"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {result ? (
          <div className="py-4 text-center space-y-2">
            <CheckCircle className="w-8 h-8 text-emerald-400 mx-auto" />
            <p className="text-xs font-semibold text-white">{t.reportSuccess}</p>
            <p className="text-[11px] text-slate-300 font-mono">
              ID: {result.reportId || 'PENDING'}
            </p>
            <button
              onClick={onClose}
              className="mt-2 w-full py-2 bg-shield-accent text-slate-950 font-bold rounded-lg text-xs"
            >
              {t.close}
            </button>
          </div>
        ) : (
          <form onSubmit={handleSubmit} className="space-y-3 text-xs">
            {error && (
              <div className="flex items-center space-x-1.5 p-2 bg-red-950/40 border border-red-800 rounded-lg text-red-300 text-[11px]">
                <AlertCircle className="w-3.5 h-3.5 shrink-0" />
                <span>{error}</span>
              </div>
            )}

            <div>
              <label className="block text-slate-300 font-medium mb-1">
                Target Domain
              </label>
              <input
                type="text"
                readOnly
                value={domain}
                className="w-full bg-shield-dark border border-shield-border rounded-lg px-2.5 py-1.5 text-slate-300 font-mono text-[11px] cursor-not-allowed"
              />
            </div>

            <div>
              <label className="block text-slate-300 font-medium mb-1">
                {t.threatCategoryLabel}
              </label>
              <select
                value={category}
                onChange={(e) => setCategory(e.target.value)}
                className="w-full bg-shield-dark border border-shield-border rounded-lg px-2.5 py-1.5 text-white text-xs focus:outline-none focus:border-shield-accent"
              >
                {THREAT_CATEGORIES.map((cat) => (
                  <option key={cat.value} value={cat.value}>
                    {cat.label}
                  </option>
                ))}
              </select>
            </div>

            <div>
              <label className="block text-slate-300 font-medium mb-1">
                {t.descriptionLabel}
              </label>
              <textarea
                value={description}
                onChange={(e) => setDescription(e.target.value)}
                placeholder="e.g. Received via SMS claiming traffic fine pending with link..."
                rows={2}
                className="w-full bg-shield-dark border border-shield-border rounded-lg p-2 text-white text-xs focus:outline-none focus:border-shield-accent resize-none placeholder:text-slate-500"
              />
            </div>

            <div className="flex space-x-2 pt-1">
              <button
                type="button"
                onClick={onClose}
                className="w-1/2 py-2 bg-shield-cardHover text-slate-300 rounded-lg font-medium hover:text-white"
              >
                Cancel
              </button>
              <button
                type="submit"
                disabled={isSubmitting}
                className="w-1/2 py-2 bg-amber-500 hover:bg-amber-600 text-slate-950 font-bold rounded-lg transition-colors disabled:opacity-50"
              >
                {isSubmitting ? t.submitting : t.submitReport}
              </button>
            </div>
          </form>
        )}
      </div>
    </div>
  );
};
