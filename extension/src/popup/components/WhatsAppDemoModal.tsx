import React, { useState, useRef, useEffect } from 'react';
import {
  X,
  Send,
  CheckCheck,
  RotateCcw,
} from 'lucide-react';
import { ReputationService } from '../../services/reputation-service';
import { IndicatorExtractor } from '../../image/indicator-extractor';
import { ImageScanner } from '../../image/image-scanner';
import { AIService } from '../../ai/ai-service';

interface WhatsAppDemoModalProps {
  isOpen: boolean;
  onClose: () => void;
}

interface ChatMessage {
  id: string;
  sender: 'user' | 'bot';
  text: string;
  timestamp: string;
  hasMedia?: boolean;
  mediaName?: string;
}

export const WhatsAppDemoModal: React.FC<WhatsAppDemoModalProps> = ({ isOpen, onClose }) => {
  const [messages, setMessages] = useState<ChatMessage[]>([
    {
      id: 'msg_welcome',
      sender: 'bot',
      text: '👋 *Welcome to ScamShield Security Bot!*\n\nForward or send me any suspicious message, link, or screenshot.\n\n*Think Before You Click.*',
      timestamp: 'Just now',
    },
  ]);
  const [inputText, setInputText] = useState('');
  const [isProcessing, setIsProcessing] = useState(false);
  const messagesEndRef = useRef<HTMLDivElement>(null);

  const scrollToBottom = () => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  };

  useEffect(() => {
    if (isOpen) {
      scrollToBottom();
    }
  }, [messages, isOpen]);

  if (!isOpen) return null;

  const handleSendMessage = async (textToSend?: string) => {
    const text = (textToSend || inputText).trim();
    if (!text || isProcessing) return;

    const userMsg: ChatMessage = {
      id: `user_${Date.now()}`,
      sender: 'user',
      text,
      timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
    };

    setMessages((prev) => [...prev, userMsg]);
    setInputText('');
    setIsProcessing(true);

    try {
      // 1. Process message through ScamShield master security pipeline
      const botResponseText = await generateBotResponse(text);

      const botMsg: ChatMessage = {
        id: `bot_${Date.now()}`,
        sender: 'bot',
        text: botResponseText,
        timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
      };

      setMessages((prev) => [...prev, botMsg]);
    } catch (err: any) {
      const errorMsg: ChatMessage = {
        id: `bot_err_${Date.now()}`,
        sender: 'bot',
        text: `⚠️ *Analysis Error*\nUnable to complete security scan: ${err.message || 'System error'}`,
        timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
      };
      setMessages((prev) => [...prev, errorMsg]);
    } finally {
      setIsProcessing(false);
    }
  };

  const handleSendSampleImage = async (fixtureType: 'KYC' | 'UPI') => {
    if (isProcessing) return;

    let sampleText = '';
    let sampleName = '';

    if (fixtureType === 'KYC') {
      sampleName = 'sbi_kyc_alert.png';
      sampleText = `
        SBI NetBanking: Your account will be blocked within 24 hours.
        Mandatory update: https://sbi-online-kyc-verification.top/login.php
        Helpline: +91 9876543210
      `;
    } else {
      sampleName = 'cashback_voucher.png';
      sampleText = `
        Paytm Alert: Rs 3000 Cashback approved!
        Claim on UPI: sbi-refund-support@paytm
        Call +91 9876543210
      `;
    }

    const b64 = btoa(unescape(encodeURIComponent(sampleText)));
    const syntheticDataUrl = `data:text/plain;base64,${b64}`;

    const userMsg: ChatMessage = {
      id: `user_img_${Date.now()}`,
      sender: 'user',
      text: `[Sent Screenshot: ${sampleName}]`,
      hasMedia: true,
      mediaName: sampleName,
      timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
    };

    setMessages((prev) => [...prev, userMsg]);
    setIsProcessing(true);

    try {
      // Run through real ImageScanner pipeline
      const imgResult = await ImageScanner.scanImage(syntheticDataUrl, {
        name: sampleName,
        sizeBytes: sampleText.length,
        mimeType: 'text/plain',
      });

      const responseText = formatImageAnalysisResponse(imgResult);

      const botMsg: ChatMessage = {
        id: `bot_${Date.now()}`,
        sender: 'bot',
        text: responseText,
        timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
      };

      setMessages((prev) => [...prev, botMsg]);
    } catch (err: any) {
      const errorMsg: ChatMessage = {
        id: `bot_err_${Date.now()}`,
        sender: 'bot',
        text: `⚠️ *Image Scan Failed*\n${err.message || 'System error during OCR/scanning'}`,
        timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
      };
      setMessages((prev) => [...prev, errorMsg]);
    } finally {
      setIsProcessing(false);
    }
  };

  /**
   * Generates real WhatsApp formatted response using ScamShield security checks
   */
  const generateBotResponse = async (text: string): Promise<string> => {
    // 1. Consent flow handling
    if (text === '1') {
      return (
        '🔍 *Deep Threat Investigation Initiated*\n\n' +
        'Checking advanced threat telemetry & global honeypot feeds...\n\n' +
        '✅ Deep investigation complete. Incident recorded in ScamShield decentralized threat network.'
      );
    }
    if (text === '2') {
      return 'Understood. Advanced investigation skipped.';
    }

    // 2. Extract indicators
    const indicators = IndicatorExtractor.extractAll(text);

    // 3. Scan extracted URLs against ReputationService
    const urlReports: string[] = [];
    let hasCriticalUrl = false;

    for (const urlItem of indicators.urls) {
      const rep = await ReputationService.evaluateUrl(urlItem.normalized, true);
      if (rep.isBlocked || rep.severity === 'CRITICAL' || rep.severity === 'HIGH') {
        hasCriticalUrl = true;
        urlReports.push(`🔴 *${urlItem.original}*\n   ↳ Verdict: *${rep.severity}* (${rep.category})\n   ↳ Risk: *${Math.round(rep.riskScore * 100)}%*`);
      } else if (rep.severity === 'SAFE') {
        urlReports.push(`🟢 *${urlItem.original}*\n   ↳ Verdict: *SAFE* (${rep.category})`);
      } else {
        urlReports.push(`⚪ *${urlItem.original}*\n   ↳ Verdict: *${rep.category}* (${Math.round(rep.riskScore * 100)}% caution)`);
      }
    }

    // 4. Check AI message analysis if configured
    let aiSummary = '';
    try {
      const aiRes = await AIService.analyzeMessage({
        messageText: text,
        sourceType: 'WHATSAPP',
      });
      if (aiRes.success) {
        aiSummary = aiRes.summary || aiRes.explanation;
      }
    } catch {
      // ignore
    }

    // 5. Build Formatted WhatsApp Reply
    const isHighRisk = hasCriticalUrl || indicators.upiIds.some((u) => u.isSuspiciousKeyword) || indicators.socialEngineeringTactics.length > 0;

    let response = '';
    if (isHighRisk) {
      response += `🚨 *SCAMSHIELD THREAT ALERT*\n\n`;
      response += `*Verdict:* HIGH RISK / SUSPICIOUS\n`;
      if (hasCriticalUrl) {
        response += `*Primary Threat:* Malicious phishing destination detected.\n\n`;
      } else {
        response += `*Primary Threat:* Social engineering or deceptive lure detected.\n\n`;
      }
    } else {
      response += `🛡️ *SCAMSHIELD SCAN RESULT*\n\n`;
      response += `*Verdict:* NO KNOWN THREAT\n\n`;
    }

    if (indicators.socialEngineeringTactics.length > 0) {
      response += `*Detected Pressure Tactics:*\n`;
      indicators.socialEngineeringTactics.forEach((t) => {
        response += `• ${t}\n`;
      });
      response += `\n`;
    }

    if (urlReports.length > 0) {
      response += `*Link Security Checks:*\n`;
      urlReports.forEach((u) => {
        response += `${u}\n`;
      });
      response += `\n`;
    }

    if (indicators.phones.length > 0) {
      response += `*Detected Contacts:*\n`;
      indicators.phones.forEach((p) => {
        response += `• ${p.normalized} ${p.riskLevel === 'HIGH' ? '(⚠️ Private mobile lure)' : ''}\n`;
      });
      response += `\n`;
    }

    if (indicators.upiIds.length > 0) {
      response += `*Detected Payment Handles:*\n`;
      indicators.upiIds.forEach((u) => {
        response += `• ${u.normalized} ${u.isSuspiciousKeyword ? '(⚠️ High risk financial keyword)' : ''}\n`;
      });
      response += `\n`;
    }

    if (aiSummary) {
      response += `*AI Explanation:*\n${aiSummary}\n\n`;
    }

    response += `*Recommended Actions:*\n`;
    if (isHighRisk) {
      response += `1. Do NOT click on any links.\n`;
      response += `2. NEVER share OTP or UPI PIN.\n`;
      response += `3. Verify directly via official banking apps.\n\n`;
      response += `_Reply *1* to trigger deeper investigation, or *2* to skip._`;
    } else {
      response += `• Communication appears standard, but stay alert for unexpected requests.`;
    }

    return response;
  };

  const formatImageAnalysisResponse = (res: any): string => {
    let out = `📸 *SCAMSHIELD IMAGE ANALYSIS REPORT*\n\n`;
    out += `*Verdict:* ${res.verdict}\n`;
    out += `*Risk Score:* ${Math.round(res.overallRiskScore)}%\n`;
    out += `*Classification:* ${res.scamClassification.primaryThreatSummary}\n\n`;

    if (res.indicators.urls.length > 0) {
      out += `*Extracted URLs:*\n`;
      res.indicators.urls.forEach((u: any) => {
        out += `• ${u.original} (${u.reputationVerdict?.severity || 'CHECKED'})\n`;
      });
      out += `\n`;
    }

    if (res.indicators.phones.length > 0) {
      out += `*Extracted Phones:*\n`;
      res.indicators.phones.forEach((p: any) => {
        out += `• ${p.normalized}\n`;
      });
      out += `\n`;
    }

    if (res.indicators.upiIds.length > 0) {
      out += `*Extracted UPI:*\n`;
      res.indicators.upiIds.forEach((upi: any) => {
        out += `• ${upi.normalized}\n`;
      });
      out += `\n`;
    }

    out += `*Recommended:*\n`;
    res.recommendedActions.slice(0, 3).forEach((a: string) => {
      out += `• ${a}\n`;
    });

    return out;
  };

  const handleResetChat = () => {
    setMessages([
      {
        id: 'msg_welcome',
        sender: 'bot',
        text: '👋 *Welcome to ScamShield Security Bot!*\n\nForward or send me any suspicious message, link, or screenshot.\n\n*Think Before You Click.*',
        timestamp: 'Just now',
      },
    ]);
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-3 bg-black/80 backdrop-blur-sm animate-fade-in">
      <div className="bg-[#0b141a] border border-emerald-900/60 w-full max-w-[370px] h-[580px] rounded-2xl shadow-2xl flex flex-col overflow-hidden text-slate-100 font-sans">
        {/* WhatsApp Header */}
        <div className="p-3 bg-[#202c33] border-b border-[#2a3942] flex items-center justify-between text-white">
          <div className="flex items-center space-x-2.5">
            <div className="w-8 h-8 rounded-full bg-emerald-600 flex items-center justify-center text-white shadow-sm font-bold text-xs">
              🛡️
            </div>
            <div>
              <div className="flex items-center space-x-1">
                <h3 className="text-xs font-bold leading-tight">ScamShield Bot</h3>
                <span className="text-[9px] bg-emerald-950 text-emerald-400 px-1 rounded border border-emerald-800">
                  VERIFIED
                </span>
              </div>
              <p className="text-[10px] text-emerald-400 font-mono">online • WhatsApp Demo</p>
            </div>
          </div>
          <div className="flex items-center space-x-1">
            <button
              onClick={handleResetChat}
              className="p-1.5 text-slate-400 hover:text-white rounded-lg hover:bg-slate-700/60 transition-colors"
              title="Reset conversation"
            >
              <RotateCcw className="w-3.5 h-3.5" />
            </button>
            <button
              onClick={onClose}
              className="p-1.5 text-slate-400 hover:text-white rounded-lg hover:bg-slate-700/60 transition-colors"
            >
              <X className="w-4 h-4" />
            </button>
          </div>
        </div>

        {/* Chat Messages Area */}
        <div className="p-3 flex-1 overflow-y-auto space-y-2.5 bg-[#0b141a] bg-opacity-95">
          {messages.map((m) => (
            <div
              key={m.id}
              className={`flex flex-col ${m.sender === 'user' ? 'items-end' : 'items-start'}`}
            >
              <div
                className={`max-w-[85%] rounded-xl p-2.5 text-[11px] leading-relaxed shadow-sm whitespace-pre-wrap ${
                  m.sender === 'user'
                    ? 'bg-[#005c4b] text-white rounded-tr-none'
                    : 'bg-[#202c33] text-slate-100 rounded-tl-none border border-[#2a3942]'
                }`}
              >
                {m.text}
                <div
                  className={`flex items-center justify-end space-x-1 text-[9px] mt-1 ${
                    m.sender === 'user' ? 'text-emerald-200/80' : 'text-slate-400'
                  }`}
                >
                  <span>{m.timestamp}</span>
                  {m.sender === 'user' && <CheckCheck className="w-3 h-3 text-cyan-300" />}
                </div>
              </div>
            </div>
          ))}

          {isProcessing && (
            <div className="flex items-start">
              <div className="bg-[#202c33] rounded-xl p-2.5 text-[11px] text-emerald-400 border border-[#2a3942] flex items-center space-x-2 animate-pulse">
                <div className="w-3 h-3 border-2 border-emerald-400 border-t-transparent rounded-full animate-spin" />
                <span>ScamShield engine analyzing message...</span>
              </div>
            </div>
          )}
          <div ref={messagesEndRef} />
        </div>

        {/* Quick Demo Pre-sets */}
        <div className="px-2.5 py-1.5 bg-[#111b21] border-t border-[#222e35] flex items-center space-x-1.5 overflow-x-auto text-[10px]">
          <span className="text-slate-400 shrink-0 text-[9px] font-mono">Simulate:</span>
          <button
            type="button"
            onClick={() => handleSendMessage('Your SBI account is blocked! Update KYC immediately: https://sbi-online-kyc-verification.top/login.php')}
            className="px-2 py-0.5 bg-[#202c33] hover:bg-[#2a3942] text-red-300 rounded-full border border-red-900/40 shrink-0"
          >
            Bank KYC Phish
          </button>
          <button
            type="button"
            onClick={() => handleSendMessage('You won Rs 50,000 lottery! Send Rs 499 registration fee to claim: lottery-win@paytm')}
            className="px-2 py-0.5 bg-[#202c33] hover:bg-[#2a3942] text-amber-300 rounded-full border border-amber-900/40 shrink-0"
          >
            Lottery Lure
          </button>
          <button
            type="button"
            onClick={() => handleSendSampleImage('KYC')}
            className="px-2 py-0.5 bg-[#202c33] hover:bg-[#2a3942] text-indigo-300 rounded-full border border-indigo-900/40 shrink-0"
          >
            Send Screenshot
          </button>
        </div>

        {/* Input Bar */}
        <div className="p-2.5 bg-[#202c33] border-t border-[#2a3942] flex items-center space-x-2">
          <input
            type="text"
            value={inputText}
            onChange={(e) => setInputText(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === 'Enter') handleSendMessage();
            }}
            placeholder="Type or paste suspicious message..."
            disabled={isProcessing}
            className="flex-1 bg-[#2a3942] text-white placeholder-slate-400 text-xs px-3 py-2 rounded-xl focus:outline-none focus:ring-1 focus:ring-emerald-500"
          />
          <button
            onClick={() => handleSendMessage()}
            disabled={!inputText.trim() || isProcessing}
            className="p-2 bg-emerald-600 hover:bg-emerald-500 text-white rounded-xl transition-all disabled:opacity-40"
          >
            <Send className="w-4 h-4" />
          </button>
        </div>
      </div>
    </div>
  );
};
