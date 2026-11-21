import React, { useState } from 'react';
import {
  X,
  Upload,
  Image as ImageIcon,
  AlertTriangle,
  ShieldCheck,
  ShieldAlert,
  QrCode,
  Phone,
  CreditCard,
  ExternalLink,
  ChevronDown,
  ChevronUp,
  FileText,
  RotateCcw,
  Sparkles,
} from 'lucide-react';
import { ImageScanner } from '../../image/image-scanner';
import { ImageScamAnalysisResult } from '../../image/types';

interface ImageScamScannerModalProps {
  isOpen: boolean;
  onClose: () => void;
}

export const ImageScamScannerModal: React.FC<ImageScamScannerModalProps> = ({ isOpen, onClose }) => {
  const [selectedImage, setSelectedImage] = useState<string | null>(null);
  const [imageMeta, setImageMeta] = useState<{ name: string; sizeBytes: number; mimeType: string } | null>(null);
  const [language, setLanguage] = useState<'eng' | 'hin' | 'mar'>('eng');
  const [isScanning, setIsScanning] = useState(false);
  const [scanStage, setScanStage] = useState<string | null>(null);
  const [result, setResult] = useState<ImageScamAnalysisResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [showOcrText, setShowOcrText] = useState(false);

  if (!isOpen) return null;

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (file) {
      processFile(file);
    }
  };

  const processFile = (file: File) => {
    setError(null);
    setResult(null);

    if (file.size > 15 * 1024 * 1024) {
      setError('File size exceeds maximum allowed limit (15MB).');
      return;
    }

    const reader = new FileReader();
    reader.onload = () => {
      const dataUrl = reader.result as string;
      setSelectedImage(dataUrl);
      setImageMeta({
        name: file.name,
        sizeBytes: file.size,
        mimeType: file.type || 'image/png',
      });
    };
    reader.onerror = () => setError('Failed to read selected image file.');
    reader.readAsDataURL(file);
  };

  const handlePaste = (e: React.ClipboardEvent) => {
    const items = e.clipboardData?.items;
    if (items) {
      for (let i = 0; i < items.length; i++) {
        if (items[i].type.startsWith('image/')) {
          const file = items[i].getAsFile();
          if (file) {
            processFile(file);
            return;
          }
        }
      }
    }
  };

  const loadSampleFixture = (type: 'KYC' | 'UPI' | 'UTILITY' | 'LEGIT') => {
    setError(null);
    setResult(null);

    let sampleText = '';
    let sampleName = '';

    if (type === 'KYC') {
      sampleName = 'sample_sbi_kyc_phishing.png';
      sampleText = `
        IMPORTANT NOTICE: State Bank of India
        Your SBI NetBanking account will be blocked within 24 hours.
        Complete your mandatory KYC update immediately:
        https://sbi-online-kyc-verification.top/login.php
        Support helpline: +91 9876543210
        Refund desk: sbi-support-desk@paytm
      `;
    } else if (type === 'UPI') {
      sampleName = 'sample_paytm_cashback_fraud.png';
      sampleText = `
        Congratulations! You have received a cashback voucher of Rs 3,500.
        To claim, approve collect request on UPI:
        upi://pay?pa=cashback-rewards@upi&pn=PayTM+Cashback&am=3500
        Hurry up, expiring today! Call 9876543210.
      `;
    } else if (type === 'UTILITY') {
      sampleName = 'sample_electricity_bill_scam.png';
      sampleText = `
        Dear Consumer, Your electricity power will be disconnected today at 9:30 PM
        because previous month bill was not updated.
        Turant contact our electricity officer at +91 9812345678 or update via:
        https://fake-challan-pay.online/pay
      `;
    } else {
      sampleName = 'sample_legitimate_order.png';
      sampleText = `
        Your Amazon.in order #402-9182371-928172 has been dispatched.
        Track shipment directly in official app:
        https://amazon.in/orders
        No OTP or action required from your side.
      `;
    }

    const b64 = btoa(unescape(encodeURIComponent(sampleText)));
    const syntheticDataUrl = `data:text/plain;base64,${b64}`;

    setSelectedImage(syntheticDataUrl);
    setImageMeta({
      name: sampleName,
      sizeBytes: sampleText.length,
      mimeType: 'image/png',
    });
  };

  const handleStartScan = async () => {
    if (!selectedImage || !imageMeta) return;

    setIsScanning(true);
    setError(null);
    setScanStage('Decoding embedded QR codes...');

    try {
      setTimeout(() => setScanStage('Performing OCR character extraction (English/Hindi/Marathi)...'), 300);
      setTimeout(() => setScanStage('Extracting URLs, phone numbers, and UPI handles...'), 700);
      setTimeout(() => setScanStage('Running indicators through ScamShield security reputation engine...'), 1100);

      const res = await ImageScanner.scanImage(selectedImage, imageMeta, language);
      setResult(res);
    } catch (err: any) {
      setError(err.message || 'Image analysis failed.');
    } finally {
      setIsScanning(false);
      setScanStage(null);
    }
  };

  const handleReset = () => {
    setSelectedImage(null);
    setImageMeta(null);
    setResult(null);
    setError(null);
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-3 bg-black/80 backdrop-blur-sm animate-fade-in">
      <div
        onPaste={handlePaste}
        className="bg-shield-card border border-shield-border w-full max-w-[370px] max-h-[580px] rounded-2xl shadow-2xl flex flex-col overflow-hidden text-slate-200"
      >
        {/* Modal Header */}
        <div className="p-3.5 border-b border-shield-border flex items-center justify-between bg-slate-900/60">
          <div className="flex items-center space-x-2">
            <div className="p-1.5 rounded-lg bg-indigo-950/80 border border-indigo-700/50 text-indigo-400">
              <ImageIcon className="w-4 h-4" />
            </div>
            <div>
              <h3 className="text-xs font-bold text-white leading-tight">Image Scam Scanner</h3>
              <p className="text-[10px] text-slate-400">OCR & Visual Threat Intelligence</p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-1 text-slate-400 hover:text-white rounded-lg hover:bg-slate-800 transition-colors"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Modal Body */}
        <div className="p-3.5 overflow-y-auto space-y-3.5 flex-1">
          {error && (
            <div className="p-2.5 bg-red-950/60 border border-red-800/60 rounded-xl text-red-300 text-xs flex items-start space-x-2">
              <ShieldAlert className="w-4 h-4 shrink-0 text-red-400 mt-0.5" />
              <span>{error}</span>
            </div>
          )}

          {!result ? (
            <div className="space-y-3">
              {/* Image Upload Dropzone */}
              {!selectedImage ? (
                <div
                  className="border-2 border-dashed border-shield-border hover:border-indigo-500/60 rounded-xl p-5 text-center bg-slate-900/40 hover:bg-slate-900/70 transition-all cursor-pointer group"
                  onClick={() => document.getElementById('image-file-input')?.click()}
                >
                  <input
                    id="image-file-input"
                    type="file"
                    accept="image/*"
                    className="hidden"
                    onChange={handleFileChange}
                  />
                  <Upload className="w-8 h-8 mx-auto text-slate-400 group-hover:text-indigo-400 transition-colors mb-2" />
                  <p className="text-xs font-semibold text-white">Click to upload screenshot</p>
                  <p className="text-[10px] text-slate-400 mt-1">or drag & drop / paste image (Ctrl+V)</p>
                  <span className="inline-block mt-2 text-[9px] px-2 py-0.5 rounded bg-slate-800 text-slate-400 border border-slate-700 font-mono">
                    PNG, JPG, WEBP up to 15MB
                  </span>
                </div>
              ) : (
                /* Image Preview Box */
                <div className="p-3 bg-slate-900/60 border border-shield-border rounded-xl space-y-2">
                  <div className="flex items-center justify-between text-xs">
                    <span className="font-semibold text-white truncate max-w-[200px]">
                      {imageMeta?.name || 'Selected Image'}
                    </span>
                    <button
                      onClick={handleReset}
                      className="text-[10px] text-red-400 hover:text-red-300 underline"
                    >
                      Remove
                    </button>
                  </div>
                  <div className="h-28 w-full bg-slate-950 rounded-lg overflow-hidden border border-slate-800 flex items-center justify-center">
                    {selectedImage.startsWith('data:image/') ? (
                      <img src={selectedImage} alt="Preview" className="h-full w-full object-contain" />
                    ) : (
                      <div className="text-center p-2">
                        <FileText className="w-6 h-6 mx-auto text-indigo-400 mb-1" />
                        <span className="text-[10px] text-slate-400">Synthetic Scam Test Fixture Loaded</span>
                      </div>
                    )}
                  </div>
                </div>
              )}

              {/* Quick Sample Demo Fixtures */}
              {!selectedImage && (
                <div className="space-y-1.5 pt-1">
                  <span className="text-[10px] font-semibold text-slate-400 uppercase tracking-wider block">
                    Quick Hackathon Demo Fixtures:
                  </span>
                  <div className="grid grid-cols-2 gap-1.5 text-[10px]">
                    <button
                      type="button"
                      onClick={() => loadSampleFixture('KYC')}
                      className="p-1.5 bg-slate-900/60 hover:bg-slate-800 border border-slate-700/60 rounded-lg text-left truncate text-red-300"
                    >
                      🏦 Fake SBI KYC Alert
                    </button>
                    <button
                      type="button"
                      onClick={() => loadSampleFixture('UPI')}
                      className="p-1.5 bg-slate-900/60 hover:bg-slate-800 border border-slate-700/60 rounded-lg text-left truncate text-amber-300"
                    >
                      💸 Fake Paytm Cashback
                    </button>
                    <button
                      type="button"
                      onClick={() => loadSampleFixture('UTILITY')}
                      className="p-1.5 bg-slate-900/60 hover:bg-slate-800 border border-slate-700/60 rounded-lg text-left truncate text-orange-300"
                    >
                      ⚡ Bijli Bill Fraud
                    </button>
                    <button
                      type="button"
                      onClick={() => loadSampleFixture('LEGIT')}
                      className="p-1.5 bg-slate-900/60 hover:bg-slate-800 border border-slate-700/60 rounded-lg text-left truncate text-emerald-300"
                    >
                      📦 Real Amazon Order
                    </button>
                  </div>
                </div>
              )}

              {/* Language Selection & Analyze Button */}
              {selectedImage && (
                <div className="space-y-2 pt-1">
                  <div className="flex items-center justify-between text-xs">
                    <span className="text-slate-400 text-[11px]">OCR Language:</span>
                    <div className="flex space-x-1">
                      {(['eng', 'hin', 'mar'] as const).map((l) => (
                        <button
                          key={l}
                          type="button"
                          onClick={() => setLanguage(l)}
                          className={`px-2 py-0.5 rounded text-[10px] font-mono uppercase transition-colors ${
                            language === l
                              ? 'bg-indigo-600 text-white font-bold'
                              : 'bg-slate-800 text-slate-400 hover:text-slate-200'
                          }`}
                        >
                          {l}
                        </button>
                      ))}
                    </div>
                  </div>

                  <button
                    onClick={handleStartScan}
                    disabled={isScanning}
                    className="w-full py-2.5 px-4 bg-gradient-to-r from-indigo-600 to-purple-600 hover:from-indigo-500 hover:to-purple-500 text-white rounded-xl text-xs font-bold transition-all shadow-md active:scale-[0.99] disabled:opacity-50 flex items-center justify-center space-x-2"
                  >
                    {isScanning ? (
                      <>
                        <div className="w-3.5 h-3.5 border-2 border-white border-t-transparent rounded-full animate-spin" />
                        <span>{scanStage || 'Analyzing Image Security...'}</span>
                      </>
                    ) : (
                      <>
                        <Sparkles className="w-3.5 h-3.5 text-indigo-200" />
                        <span>Analyze Screenshot / Image</span>
                      </>
                    )}
                  </button>
                </div>
              )}
            </div>
          ) : (
            /* Results View */
            <div className="space-y-3 animate-fade-in text-xs">
              {/* Verdict Header Card */}
              <div
                className={`p-3 rounded-xl border flex items-center justify-between ${
                  result.verdict === 'CRITICAL' || result.verdict === 'HIGH'
                    ? 'bg-red-950/40 border-red-700/60 text-red-200'
                    : result.verdict === 'SUSPICIOUS'
                    ? 'bg-amber-950/40 border-amber-700/60 text-amber-200'
                    : 'bg-emerald-950/40 border-emerald-700/60 text-emerald-200'
                }`}
              >
                <div className="flex items-center space-x-2.5">
                  {result.verdict === 'CRITICAL' || result.verdict === 'HIGH' ? (
                    <ShieldAlert className="w-5 h-5 text-red-400 shrink-0" />
                  ) : result.verdict === 'SUSPICIOUS' ? (
                    <AlertTriangle className="w-5 h-5 text-amber-400 shrink-0" />
                  ) : (
                    <ShieldCheck className="w-5 h-5 text-emerald-400 shrink-0" />
                  )}
                  <div>
                    <span className="font-bold text-xs uppercase block">
                      {result.verdict === 'CRITICAL' || result.verdict === 'HIGH'
                        ? 'High-Risk Scam Detected'
                        : result.verdict === 'SUSPICIOUS'
                        ? 'Suspicious Content'
                        : 'No Obvious Scam Signals'}
                    </span>
                    <span className="text-[10px] opacity-80">{result.scamClassification.primaryThreatSummary}</span>
                  </div>
                </div>
                <div className="text-right shrink-0">
                  <span className="font-mono font-bold text-sm">{Math.round(result.overallRiskScore)}%</span>
                  <span className="block text-[9px] opacity-75">Risk Score</span>
                </div>
              </div>

              {/* Detected Indicators List */}
              <div className="space-y-1.5">
                <span className="text-[10px] font-semibold text-slate-400 uppercase tracking-wider block">
                  Extracted Threat Indicators:
                </span>

                {/* Social Engineering Signals */}
                {result.scamClassification.socialEngineeringTactics.map((tactic, idx) => (
                  <div key={idx} className="p-2 bg-slate-900/70 border border-amber-800/40 rounded-lg flex items-center space-x-2 text-[11px]">
                    <AlertTriangle className="w-3.5 h-3.5 text-amber-400 shrink-0" />
                    <span className="text-amber-200">{tactic}</span>
                  </div>
                ))}

                {/* Extracted URLs */}
                {result.indicators.urls.map((u, idx) => (
                  <div key={idx} className="p-2 bg-slate-900/70 border border-shield-border rounded-lg space-y-1 text-[11px]">
                    <div className="flex items-center justify-between">
                      <div className="flex items-center space-x-1.5 truncate">
                        <ExternalLink className="w-3.5 h-3.5 text-indigo-400 shrink-0" />
                        <span className="font-mono text-white truncate">{u.original}</span>
                      </div>
                      <span className={`text-[9px] font-mono px-1.5 py-0.2 rounded shrink-0 ml-1 ${
                        u.reputationVerdict?.isBlocked ? 'bg-red-950 text-red-300 border border-red-800' : 'bg-slate-800 text-slate-300'
                      }`}>
                        {u.reputationVerdict?.severity || 'CHECKED'}
                      </span>
                    </div>
                  </div>
                ))}

                {/* Extracted Phones */}
                {result.indicators.phones.map((p, idx) => (
                  <div key={idx} className="p-2 bg-slate-900/70 border border-shield-border rounded-lg flex items-center justify-between text-[11px]">
                    <div className="flex items-center space-x-1.5">
                      <Phone className="w-3.5 h-3.5 text-emerald-400 shrink-0" />
                      <span className="font-mono text-white">{p.normalized}</span>
                    </div>
                    {p.riskLevel === 'HIGH' && (
                      <span className="text-[9px] px-1.5 py-0.2 rounded bg-amber-950/80 text-amber-300 border border-amber-800">
                        Private Contact Lure
                      </span>
                    )}
                  </div>
                ))}

                {/* Extracted UPI */}
                {result.indicators.upiIds.map((upi, idx) => (
                  <div key={idx} className="p-2 bg-slate-900/70 border border-shield-border rounded-lg flex items-center justify-between text-[11px]">
                    <div className="flex items-center space-x-1.5">
                      <CreditCard className="w-3.5 h-3.5 text-cyan-400 shrink-0" />
                      <span className="font-mono text-white">{upi.normalized}</span>
                    </div>
                    {upi.isSuspiciousKeyword && (
                      <span className="text-[9px] px-1.5 py-0.2 rounded bg-red-950/80 text-red-300 border border-red-800">
                        Fraud Keyword
                      </span>
                    )}
                  </div>
                ))}

                {/* Extracted QR */}
                {result.indicators.qrCodes.map((qr, idx) => (
                  <div key={idx} className="p-2 bg-slate-900/70 border border-indigo-800/40 rounded-lg space-y-1 text-[11px]">
                    <div className="flex items-center space-x-1.5">
                      <QrCode className="w-3.5 h-3.5 text-indigo-400 shrink-0" />
                      <span className="font-semibold text-indigo-300">Decoded QR ({qr.type})</span>
                    </div>
                    <p className="font-mono text-[10px] text-slate-300 truncate">{qr.decodedUrl || qr.decodedUpi?.original || qr.rawData}</p>
                  </div>
                ))}
              </div>

              {/* Actionable Recommendations */}
              <div className="p-2.5 bg-slate-900/80 border border-shield-border rounded-xl space-y-1">
                <span className="text-[10px] font-semibold text-slate-300 uppercase tracking-wider block">
                  Recommended Safety Actions:
                </span>
                <ul className="space-y-1 text-[11px] text-slate-300">
                  {result.recommendedActions.map((action, idx) => (
                    <li key={idx} className="flex items-start space-x-1.5">
                      <span className="text-shield-accent shrink-0">•</span>
                      <span>{action}</span>
                    </li>
                  ))}
                </ul>
              </div>

              {/* Collapsible Extracted OCR Text */}
              <div className="border border-shield-border/60 rounded-xl overflow-hidden">
                <button
                  type="button"
                  onClick={() => setShowOcrText(!showOcrText)}
                  className="w-full p-2 bg-slate-900/50 hover:bg-slate-900 flex items-center justify-between text-[11px] font-semibold text-slate-300"
                >
                  <span className="flex items-center space-x-1.5">
                    <FileText className="w-3 h-3 text-slate-400" />
                    <span>View Extracted OCR Text</span>
                  </span>
                  {showOcrText ? <ChevronUp className="w-3.5 h-3.5" /> : <ChevronDown className="w-3.5 h-3.5" />}
                </button>
                {showOcrText && (
                  <div className="p-2 bg-slate-950 font-mono text-[10px] text-slate-300 whitespace-pre-wrap max-h-32 overflow-y-auto">
                    {result.ocrResult.extractedText || 'No printable text recognized by OCR.'}
                  </div>
                )}
              </div>

              {/* Reset / Scan Another Button */}
              <button
                onClick={handleReset}
                className="w-full py-2 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded-xl text-xs font-semibold transition-colors flex items-center justify-center space-x-1.5"
              >
                <RotateCcw className="w-3.5 h-3.5" />
                <span>Scan Another Image</span>
              </button>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
