'use client';

import { useState } from 'react';
import { useRouter } from 'next/navigation';

export default function ReportScamPage() {
  const router = useRouter();
  const [activeTab, setActiveTab] = useState<'TEXT' | 'URL' | 'IDENTIFIER' | 'FILE'>('TEXT');
  const [title, setTitle] = useState('');
  const [description, setDescription] = useState('');
  const [content, setContent] = useState('');
  const [category, setCategory] = useState('BANKING_KYC');
  const [platform, setPlatform] = useState('SMS');
  const [language, setLanguage] = useState('en');
  const [file, setFile] = useState<File | null>(null);

  const [analyzing, setAnalyzing] = useState(false);
  const [analysisPreview, setAnalysisPreview] = useState<any>(null);
  const [submitting, setSubmitting] = useState(false);
  const [errorMsg, setErrorMsg] = useState('');

  // Handle Live Scan Preview
  const handleScanPreview = async () => {
    if (activeTab === 'FILE' && !file) {
      setErrorMsg('Please select a file to scan');
      return;
    }
    if (activeTab !== 'FILE' && !content.trim()) {
      setErrorMsg('Please enter threat content to analyze');
      return;
    }

    setAnalyzing(true);
    setErrorMsg('');
    setAnalysisPreview(null);

    try {
      if (activeTab === 'FILE' && file) {
        const formData = new FormData();
        formData.append('file', file);
        const res = await fetch('/api/analyze', {
          method: 'POST',
          body: formData,
        });
        const data = await res.json();
        if (data.success) {
          setAnalysisPreview(data.result);
          if (!content) {
            setContent(data.result.ocrText || `[Document: ${file.name}] ${data.result.explanation}`);
          }
          if (data.result.category && data.result.category !== 'LEGITIMATE_COMMUNICATION') {
            setCategory(data.result.category);
          }
        } else {
          setErrorMsg(data.error || 'Document scan failed');
        }
      } else {
        const res = await fetch('/api/analyze', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            text: content,
            type: activeTab === 'URL' ? 'URL' : activeTab === 'IDENTIFIER' ? 'PHONE' : 'TEXT',
            language,
          }),
        });
        const data = await res.json();
        if (data.success) {
          setAnalysisPreview(data.result);
          if (data.result.category && data.result.category !== 'LEGITIMATE_COMMUNICATION') {
            setCategory(data.result.category);
          }
        } else {
          setErrorMsg(data.error || 'Analysis failed');
        }
      }
    } catch {
      setErrorMsg('Network error while analyzing threat.');
    } finally {
      setAnalyzing(false);
    }
  };

  // Submit to Community
  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!title.trim() || !content.trim()) {
      setErrorMsg('Title and threat content are required.');
      return;
    }

    setSubmitting(true);
    setErrorMsg('');

    try {
      const res = await fetch('/api/posts', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          title,
          description,
          content,
          category,
          platform,
          language,
        }),
      });

      const data = await res.json();
      if (data.success && data.postId) {
        router.push(`/community/${data.postId}`);
      } else {
        setErrorMsg(data.error || 'Failed to submit report. Please log in.');
      }
    } catch {
      setErrorMsg('Network error while submitting report.');
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="max-w-3xl mx-auto space-y-8">
      <div>
        <h1 className="text-2xl sm:text-3xl font-bold text-white tracking-tight">
          Report a Scam or Malicious Threat
        </h1>
        <p className="text-sm text-slate-400">
          Submit suspicious messages, links, screenshots, or documents. All submissions are automatically redacted for PII and analyzed by ScamShield AI.
        </p>
      </div>

      {errorMsg && (
        <div className="p-4 rounded-xl bg-rose-950/80 border border-rose-800 text-rose-300 text-xs">
          {errorMsg}
        </div>
      )}

      {/* Tabs */}
      <div className="flex border-b border-slate-800 space-x-2">
        <button
          type="button"
          onClick={() => { setActiveTab('TEXT'); setPlatform('SMS'); }}
          className={`py-2 px-4 text-xs font-semibold border-b-2 transition-all ${
            activeTab === 'TEXT'
              ? 'border-cyan-400 text-cyan-400'
              : 'border-transparent text-slate-400 hover:text-white'
          }`}
        >
          SMS / Message
        </button>
        <button
          type="button"
          onClick={() => { setActiveTab('URL'); setPlatform('Web'); }}
          className={`py-2 px-4 text-xs font-semibold border-b-2 transition-all ${
            activeTab === 'URL'
              ? 'border-cyan-400 text-cyan-400'
              : 'border-transparent text-slate-400 hover:text-white'
          }`}
        >
          Phishing URL
        </button>
        <button
          type="button"
          onClick={() => { setActiveTab('IDENTIFIER'); setPlatform('Call'); }}
          className={`py-2 px-4 text-xs font-semibold border-b-2 transition-all ${
            activeTab === 'IDENTIFIER'
              ? 'border-cyan-400 text-cyan-400'
              : 'border-transparent text-slate-400 hover:text-white'
          }`}
        >
          Phone / UPI ID
        </button>
        <button
          type="button"
          onClick={() => { setActiveTab('FILE'); setPlatform('Document'); }}
          className={`py-2 px-4 text-xs font-semibold border-b-2 transition-all ${
            activeTab === 'FILE'
              ? 'border-cyan-400 text-cyan-400'
              : 'border-transparent text-slate-400 hover:text-white'
          }`}
        >
          Screenshot / Document
        </button>
      </div>

      <form onSubmit={handleSubmit} className="space-y-6">
        {/* Dynamic Input based on Active Tab */}
        {activeTab === 'FILE' ? (
          <div className="space-y-2">
            <label className="block text-xs font-medium text-slate-300">
              Upload Suspicious File (Image, PDF, DOCX, CSV, TXT — Max 10MB)
            </label>
            <div className="border-2 border-dashed border-slate-700 hover:border-cyan-500 rounded-xl p-6 text-center cursor-pointer transition-colors bg-slate-900/50">
              <input
                type="file"
                accept=".png,.jpg,.jpeg,.webp,.pdf,.docx,.csv,.txt"
                onChange={(e) => setFile(e.target.files?.[0] || null)}
                className="block w-full text-xs text-slate-400 file:mr-4 file:py-2 file:px-4 file:rounded-md file:border-0 file:text-xs file:font-semibold file:bg-cyan-900 file:text-cyan-300 hover:file:bg-cyan-800"
              />
              <p className="text-[11px] text-slate-500 mt-2">
                Embedded scripts and macros are safely extracted without execution.
              </p>
            </div>
          </div>
        ) : (
          <div className="space-y-2">
            <label className="block text-xs font-medium text-slate-300">
              {activeTab === 'URL'
                ? 'Target Phishing URL'
                : activeTab === 'IDENTIFIER'
                ? 'Fraudulent Phone Number or UPI Handle'
                : 'Scam Message Content'}
            </label>
            <textarea
              rows={activeTab === 'URL' || activeTab === 'IDENTIFIER' ? 2 : 4}
              value={content}
              onChange={(e) => setContent(e.target.value)}
              placeholder={
                activeTab === 'URL'
                  ? 'https://sbi-kyc-verify-portal.xyz/login...'
                  : activeTab === 'IDENTIFIER'
                  ? '+91 9876543210 or refund-nodal-officer@ybl'
                  : 'URGENT: Your bank account will be blocked today due to incomplete KYC. Update immediately...'
              }
              className="w-full p-3 rounded-xl bg-slate-900 border border-slate-800 text-white placeholder-slate-500 text-xs sm:text-sm font-mono focus:outline-none focus:border-cyan-500"
            />
          </div>
        )}

        {/* Action: Run Immediate Scan Preview */}
        <div>
          <button
            type="button"
            onClick={handleScanPreview}
            disabled={analyzing}
            className="px-4 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-cyan-400 font-semibold text-xs border border-slate-700 transition-colors flex items-center gap-2 disabled:opacity-50"
          >
            {analyzing ? (
              <>
                <svg className="animate-spin h-3.5 w-3.5 text-cyan-400" viewBox="0 0 24 24" fill="none">
                  <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                  <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8v8H4z" />
                </svg>
                <span>Running Scan Preview...</span>
              </>
            ) : (
              <>
                <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 10V3L4 14h7v7l9-11h-7z" />
                </svg>
                <span>Run ScamShield AI Pre-Scan</span>
              </>
            )}
          </button>
        </div>

        {/* Scan Preview Card */}
        {analysisPreview && (
          <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 space-y-3">
            <div className="flex items-center justify-between">
              <span className="text-xs font-bold text-slate-300">ScamShield Analysis Result</span>
              <span
                className={`px-2 py-0.5 rounded text-xs font-bold ${
                  analysisPreview.riskClassification === 'CRITICAL'
                    ? 'bg-rose-950 text-rose-300 border border-rose-800'
                    : analysisPreview.riskClassification === 'HIGH'
                    ? 'bg-orange-950 text-orange-300 border border-orange-800'
                    : 'bg-amber-950 text-amber-300 border border-amber-800'
                }`}
              >
                {analysisPreview.riskClassification} ({analysisPreview.riskScore}%)
              </span>
            </div>
            <p className="text-xs text-slate-300">{analysisPreview.explanation}</p>
            {analysisPreview.socialTactics?.length > 0 && (
              <div className="flex flex-wrap gap-1">
                {analysisPreview.socialTactics.map((t: string, i: number) => (
                  <span key={i} className="px-1.5 py-0.5 rounded bg-slate-800 text-[10px] text-cyan-300">
                    {t}
                  </span>
                ))}
              </div>
            )}
          </div>
        )}

        {/* Metadata Details */}
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
          <div className="space-y-1">
            <label className="block text-xs font-medium text-slate-300">Report Title</label>
            <input
              type="text"
              required
              value={title}
              onChange={(e) => setTitle(e.target.value)}
              placeholder="e.g. Fake SBI KYC suspension SMS with phishing link"
              className="w-full px-3 py-2 rounded-lg bg-slate-900 border border-slate-800 text-white text-xs focus:outline-none focus:border-cyan-500"
            />
          </div>

          <div className="space-y-1">
            <label className="block text-xs font-medium text-slate-300">Threat Typology</label>
            <select
              value={category}
              onChange={(e) => setCategory(e.target.value)}
              className="w-full px-3 py-2 rounded-lg bg-slate-900 border border-slate-800 text-white text-xs focus:outline-none focus:border-cyan-500"
            >
              <option value="BANKING_KYC">Banking / KYC Phishing</option>
              <option value="ELECTRICITY">Electricity Cutoff Fraud</option>
              <option value="DIGITAL_ARREST">Digital Arrest / Police Extortion</option>
              <option value="JOB_OFFER">Job / Telegram Task Scam</option>
              <option value="UPI_FRAUD">UPI / Refund Collect Scam</option>
              <option value="PHISHING_URL">Malicious URL / Fake Portal</option>
              <option value="OTHER">Other Threat</option>
            </select>
          </div>
        </div>

        <div className="space-y-1">
          <label className="block text-xs font-medium text-slate-300">Context / What Happened (Optional)</label>
          <textarea
            rows={2}
            value={description}
            onChange={(e) => setDescription(e.target.value)}
            placeholder="Explain how you received this threat, any demands made, or damage prevented..."
            className="w-full p-3 rounded-lg bg-slate-900 border border-slate-800 text-white text-xs focus:outline-none focus:border-cyan-500"
          />
        </div>

        {/* Submit Button */}
        <div className="pt-2">
          <button
            type="submit"
            disabled={submitting}
            className="w-full py-3 rounded-xl bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white font-bold text-sm shadow-lg shadow-cyan-600/30 transition-all disabled:opacity-50"
          >
            {submitting ? 'Publishing Report & Contributing to Benchmark...' : 'Publish to Community Threat Intelligence'}
          </button>
          <p className="text-[11px] text-slate-500 text-center mt-2">
            By submitting, citizen PII is automatically masked and anonymized to protect privacy while improving defense datasets.
          </p>
        </div>
      </form>
    </div>
  );
}
