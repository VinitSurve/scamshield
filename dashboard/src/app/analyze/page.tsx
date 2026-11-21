'use client';

import { useState } from 'react';

export default function LiveScannerPage() {
  const [scanType, setScanType] = useState<'TEXT' | 'URL' | 'FILE'>('TEXT');
  const [inputVal, setInputVal] = useState('');
  const [file, setFile] = useState<File | null>(null);
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<any>(null);
  const [errorMsg, setErrorMsg] = useState('');

  const handleScan = async (e: React.FormEvent) => {
    e.preventDefault();
    setErrorMsg('');
    setResult(null);

    if (scanType === 'FILE' && !file) {
      setErrorMsg('Please select a file to upload');
      return;
    }
    if (scanType !== 'FILE' && !inputVal.trim()) {
      setErrorMsg('Please enter text or URL to scan');
      return;
    }

    setLoading(true);

    try {
      if (scanType === 'FILE' && file) {
        const formData = new FormData();
        formData.append('file', file);
        const res = await fetch('/api/analyze', {
          method: 'POST',
          body: formData,
        });
        const data = await res.json();
        if (data.success) {
          setResult(data.result);
        } else {
          setErrorMsg(data.error || 'Document scan failed');
        }
      } else {
        const res = await fetch('/api/analyze', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            text: inputVal,
            type: scanType,
          }),
        });
        const data = await res.json();
        if (data.success) {
          setResult(data.result);
        } else {
          setErrorMsg(data.error || 'Scan failed');
        }
      }
    } catch {
      setErrorMsg('Network error connecting to analysis backend');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="max-w-4xl mx-auto space-y-8">
      <div>
        <h1 className="text-2xl sm:text-3xl font-bold text-white tracking-tight">
          ScamShield Multi-Modal Threat Scanner
        </h1>
        <p className="text-sm text-slate-400">
          Instant threat inspection powered by ScamShield Ensemble ML, Groq Vision OCR, and deterministic rule engines.
        </p>
      </div>

      {/* Tabs */}
      <div className="flex border-b border-slate-800 space-x-2">
        <button
          onClick={() => { setScanType('TEXT'); setInputVal(''); }}
          className={`py-2 px-4 text-xs font-semibold border-b-2 transition-all ${
            scanType === 'TEXT'
              ? 'border-cyan-400 text-cyan-400'
              : 'border-transparent text-slate-400 hover:text-white'
          }`}
        >
          Message / SMS / WhatsApp
        </button>
        <button
          onClick={() => { setScanType('URL'); setInputVal(''); }}
          className={`py-2 px-4 text-xs font-semibold border-b-2 transition-all ${
            scanType === 'URL'
              ? 'border-cyan-400 text-cyan-400'
              : 'border-transparent text-slate-400 hover:text-white'
          }`}
        >
          Phishing URL / Domain
        </button>
        <button
          onClick={() => { setScanType('FILE'); setFile(null); }}
          className={`py-2 px-4 text-xs font-semibold border-b-2 transition-all ${
            scanType === 'FILE'
              ? 'border-cyan-400 text-cyan-400'
              : 'border-transparent text-slate-400 hover:text-white'
          }`}
        >
          Screenshot / Document
        </button>
      </div>

      {/* Input Form */}
      <form onSubmit={handleScan} className="space-y-4">
        {scanType === 'FILE' ? (
          <div className="border-2 border-dashed border-slate-800 hover:border-cyan-500 rounded-xl p-8 text-center bg-slate-900/50">
            <input
              type="file"
              accept=".png,.jpg,.jpeg,.webp,.pdf,.docx,.csv,.txt"
              onChange={(e) => setFile(e.target.files?.[0] || null)}
              className="text-xs text-slate-400 file:mr-4 file:py-2 file:px-4 file:rounded-md file:border-0 file:text-xs file:font-semibold file:bg-cyan-900 file:text-cyan-300 hover:file:bg-cyan-800"
            />
            <p className="text-[11px] text-slate-500 mt-2">
              Supports PNG, JPG, PDF, DOCX, CSV. Extracted safely with macro/JS neutralization.
            </p>
          </div>
        ) : (
          <textarea
            rows={scanType === 'URL' ? 2 : 5}
            value={inputVal}
            onChange={(e) => setInputVal(e.target.value)}
            placeholder={
              scanType === 'URL'
                ? 'Enter URL: https://sbi-kyc-verify-portal.xyz/login...'
                : 'Paste message: URGENT: Dear Customer your ICICI account will be suspended today...'
            }
            className="w-full p-4 rounded-xl bg-slate-900 border border-slate-800 text-white placeholder-slate-500 text-xs sm:text-sm font-mono focus:outline-none focus:border-cyan-500"
          />
        )}

        <button
          type="submit"
          disabled={loading}
          className="w-full py-3 rounded-xl bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 font-bold text-white text-sm shadow-lg shadow-cyan-600/30 transition-all flex items-center justify-center gap-2 disabled:opacity-50"
        >
          {loading ? (
            <>
              <svg className="animate-spin h-4 w-4 text-white" viewBox="0 0 24 24" fill="none">
                <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8v8H4z" />
              </svg>
              <span>Analyzing Threat Vector...</span>
            </>
          ) : (
            <span>Run ScamShield Deep Scan</span>
          )}
        </button>
      </form>

      {errorMsg && (
        <div className="p-4 rounded-xl bg-rose-950/80 border border-rose-800 text-rose-300 text-xs">
          {errorMsg}
        </div>
      )}

      {/* Analysis Results */}
      {result && (
        <div className="p-6 sm:p-8 rounded-2xl bg-slate-900 border border-slate-800 space-y-6 animate-fadeIn">
          {/* Header Score & Verdict */}
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-slate-800 pb-5">
            <div>
              <span className="text-xs text-slate-400 font-semibold uppercase tracking-wider">
                Threat Assessment Verdict
              </span>
              <div className="flex items-center gap-3 mt-1">
                <span
                  className={`px-3 py-1 rounded-lg text-sm font-extrabold ${
                    result.riskClassification === 'CRITICAL'
                      ? 'bg-rose-950 text-rose-300 border border-rose-800'
                      : result.riskClassification === 'HIGH'
                      ? 'bg-orange-950 text-orange-300 border border-orange-800'
                      : result.riskClassification === 'SUSPICIOUS'
                      ? 'bg-amber-950 text-amber-300 border border-amber-800'
                      : 'bg-emerald-950 text-emerald-300 border border-emerald-800'
                  }`}
                >
                  {result.riskClassification} RISK
                </span>
                <span className="text-xl font-bold text-white">
                  Risk Score: {result.riskScore}%
                </span>
              </div>
            </div>

            <div className="text-right sm:text-right">
              <span className="text-[10px] text-slate-500 uppercase tracking-wider">Category</span>
              <p className="text-xs font-semibold text-cyan-400">{result.category.replace(/_/g, ' ')}</p>
            </div>
          </div>

          {/* Explanation */}
          <div className="space-y-1">
            <h4 className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Analysis Summary</h4>
            <p className="text-sm text-slate-200 leading-relaxed">{result.explanation}</p>
          </div>

          {/* OCR text if document */}
          {result.ocrText && (
            <div className="space-y-1">
              <h4 className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Extracted OCR / Document Content</h4>
              <div className="p-3 rounded-lg bg-slate-950 border border-slate-800 text-xs font-mono text-slate-300 max-h-36 overflow-y-auto">
                {result.ocrText}
              </div>
            </div>
          )}

          {/* Social Engineering Tactics */}
          {result.socialTactics && result.socialTactics.length > 0 && (
            <div className="space-y-2">
              <h4 className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Detected Social Engineering Tactics</h4>
              <div className="flex flex-wrap gap-2">
                {result.socialTactics.map((tactic: string, idx: number) => (
                  <span
                    key={idx}
                    className="px-2.5 py-1 rounded-md bg-rose-950/60 border border-rose-800/60 text-rose-300 text-xs"
                  >
                    ⚠️ {tactic}
                  </span>
                ))}
              </div>
            </div>
          )}

          {/* Extracted Indicators */}
          <div className="space-y-2">
            <h4 className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Extracted Indicators of Compromise</h4>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-xs">
              {result.extractedEntities?.urls?.length > 0 && (
                <div className="p-3 rounded-lg bg-slate-950 border border-slate-800 space-y-1">
                  <span className="text-slate-500 font-bold">URLs ({result.extractedEntities.urls.length})</span>
                  {result.extractedEntities.urls.map((u: string, i: number) => (
                    <div key={i} className="text-rose-400 font-mono break-all">{u}</div>
                  ))}
                </div>
              )}
              {result.extractedEntities?.phones?.length > 0 && (
                <div className="p-3 rounded-lg bg-slate-950 border border-slate-800 space-y-1">
                  <span className="text-slate-500 font-bold">Phone Numbers ({result.extractedEntities.phones.length})</span>
                  {result.extractedEntities.phones.map((p: string, i: number) => (
                    <div key={i} className="text-amber-400 font-mono">{p}</div>
                  ))}
                </div>
              )}
              {result.extractedEntities?.upiIds?.length > 0 && (
                <div className="p-3 rounded-lg bg-slate-950 border border-slate-800 space-y-1">
                  <span className="text-slate-500 font-bold">UPI Handles ({result.extractedEntities.upiIds.length})</span>
                  {result.extractedEntities.upiIds.map((upi: string, i: number) => (
                    <div key={i} className="text-cyan-400 font-mono">{upi}</div>
                  ))}
                </div>
              )}
            </div>
          </div>

          {/* Recommendations */}
          {result.securityRecommendations && (
            <div className="p-4 rounded-xl bg-cyan-950/30 border border-cyan-800/50 space-y-2 text-xs">
              <h4 className="font-bold text-cyan-300">Actionable Security Recommendations</h4>
              <ul className="list-disc list-inside space-y-1 text-slate-300">
                {result.securityRecommendations.map((rec: string, i: number) => (
                  <li key={i}>{rec}</li>
                ))}
              </ul>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
