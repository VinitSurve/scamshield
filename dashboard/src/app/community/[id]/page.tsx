'use client';

import { use, useEffect, useState, Suspense } from 'react';
import Link from 'next/link';

export default function PostDetailPage({
  params,
}: {
  params: Promise<{ id: string }>;
}) {
  const { id } = use(params);
  const [post, setPost] = useState<any>(null);
  const [comments, setComments] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [newComment, setNewComment] = useState('');
  const [submittingComment, setSubmittingComment] = useState(false);

  const fetchDetail = async () => {
    setLoading(true);
    try {
      const res = await fetch(`/api/posts/${id}`);
      const data = await res.json();
      if (data.success) {
        setPost(data.post);
        setComments(data.comments || []);
      }
    } catch {
      // Handled
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchDetail();
  }, [id]);

  const handleVote = async (voteType: 'UP' | 'DOWN') => {
    try {
      const res = await fetch(`/api/posts/${id}/vote`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ voteType }),
      });
      const data = await res.json();
      if (data.success) {
        fetchDetail();
      } else {
        alert(data.error || 'Please sign in to vote');
      }
    } catch {
      // Handled
    }
  };

  const handleAddComment = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newComment.trim()) return;

    setSubmittingComment(true);
    try {
      const res = await fetch(`/api/posts/${id}/comments`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ content: newComment }),
      });
      const data = await res.json();
      if (data.success) {
        setNewComment('');
        fetchDetail();
      } else {
        alert(data.error || 'Failed to post comment. Ensure you are signed in.');
      }
    } catch {
      // Handled
    } finally {
      setSubmittingComment(false);
    }
  };

  if (loading) {
    return (
      <div className="py-20 text-center text-slate-500 text-sm">
        <svg className="animate-spin h-6 w-6 text-cyan-500 mx-auto mb-2" viewBox="0 0 24 24" fill="none">
          <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
          <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8v8H4z" />
        </svg>
        Loading threat intelligence details...
      </div>
    );
  }

  if (!post) {
    return (
      <div className="py-16 text-center space-y-3">
        <p className="text-slate-400">Post not found or has been removed.</p>
        <Link href="/community" className="text-xs text-cyan-400 hover:underline">
          ← Return to Community Feed
        </Link>
      </div>
    );
  }

  return (
    <div className="max-w-4xl mx-auto space-y-8">
      {/* Back Link */}
      <Link href="/community" className="inline-flex items-center gap-1.5 text-xs text-slate-400 hover:text-white transition-colors">
        <span>← Back to Community Feed</span>
      </Link>

      {/* Main Post Card */}
      <div className="p-6 sm:p-8 rounded-2xl bg-slate-900 border border-slate-800 space-y-6">
        {/* Meta Bar */}
        <div className="flex flex-wrap items-center justify-between gap-4 border-b border-slate-800 pb-4">
          <div className="flex flex-wrap items-center gap-2">
            <span
              className={`px-2.5 py-1 rounded text-xs font-bold ${
                post.severity === 'CRITICAL'
                  ? 'bg-rose-950 text-rose-300 border border-rose-800'
                  : post.severity === 'HIGH'
                  ? 'bg-orange-950 text-orange-300 border border-orange-800'
                  : 'bg-amber-950 text-amber-300 border border-amber-800'
              }`}
            >
              {post.severity} SEVERITY
            </span>
            <span className="px-2.5 py-1 rounded text-xs font-semibold bg-cyan-950 text-cyan-300 border border-cyan-800">
              {post.verification_status.replace(/_/g, ' ')}
            </span>
            <span className="px-2.5 py-1 rounded text-xs bg-slate-800 text-slate-300">
              {post.category.replace(/_/g, ' ')}
            </span>
          </div>

          {/* Upvote & Downvote */}
          <div className="flex items-center gap-2 bg-slate-950 px-3 py-1.5 rounded-lg border border-slate-800">
            <button
              onClick={() => handleVote('UP')}
              className={`flex items-center gap-1 text-xs font-bold transition-colors ${
                post.userVote === 'UP' ? 'text-cyan-400' : 'text-slate-400 hover:text-white'
              }`}
            >
              <svg className="w-4 h-4" fill="currentColor" viewBox="0 0 20 20">
                <path fillRule="evenodd" d="M14.707 12.707a1 1 0 01-1.414 0L10 9.414l-3.293 3.293a1 1 0 01-1.414-1.414l4-4a1 1 0 011.414 0l4 4a1 1 0 010 1.414z" clipRule="evenodd" />
              </svg>
              <span>{post.upvotes}</span>
            </button>
            <span className="text-slate-700">|</span>
            <button
              onClick={() => handleVote('DOWN')}
              className={`text-xs transition-colors ${
                post.userVote === 'DOWN' ? 'text-rose-400' : 'text-slate-400 hover:text-white'
              }`}
            >
              <svg className="w-4 h-4" fill="currentColor" viewBox="0 0 20 20">
                <path fillRule="evenodd" d="M5.293 7.293a1 1 0 011.414 0L10 10.586l3.293-3.293a1 1 0 111.414 1.414l-4 4a1 1 0 01-1.414 0l-4-4a1 1 0 010-1.414z" clipRule="evenodd" />
              </svg>
            </button>
          </div>
        </div>

        {/* Title & Author Info */}
        <div className="space-y-2">
          <h1 className="text-2xl sm:text-3xl font-extrabold text-white tracking-tight">
            {post.title}
          </h1>
          <p className="text-xs text-slate-400">
            Reported by <strong className="text-slate-200">{post.author_username}</strong> (Trust Score: {post.author_trust_score}) • Platform: {post.platform} • {new Date(post.created_at).toLocaleString()}
          </p>
          {post.description && (
            <p className="text-sm text-slate-300 pt-2 leading-relaxed">
              {post.description}
            </p>
          )}
        </div>

        {/* Redacted Message Payload */}
        <div className="space-y-2">
          <div className="flex items-center justify-between text-xs text-slate-400">
            <span className="font-semibold uppercase tracking-wider">Raw Threat Content (PII Redacted)</span>
            <span className="text-emerald-400 text-[11px]">✓ Citizen Data Anonymized</span>
          </div>
          <div className="p-4 rounded-xl bg-slate-950 border border-slate-800 font-mono text-xs sm:text-sm text-slate-200 whitespace-pre-wrap leading-relaxed select-text">
            {post.content}
          </div>
        </div>

        {/* Threat Indicators & Forensic Tactics */}
        {post.extracted_indicators && post.extracted_indicators.length > 0 && (
          <div className="space-y-3 pt-2">
            <h3 className="text-xs font-bold text-slate-300 uppercase tracking-wider">
              Extracted Indicators of Compromise (IoCs) & Tactics
            </h3>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
              {post.extracted_indicators.map((indicator: any, idx: number) => {
                const isObj = typeof indicator === 'object';
                const type = isObj ? indicator.type : 'INDICATOR';
                const value = isObj ? indicator.value : indicator;
                const note = isObj ? indicator.note : '';
                return (
                  <div
                    key={idx}
                    className="p-3 rounded-lg bg-slate-950/80 border border-slate-800/80 flex flex-col gap-1 text-xs"
                  >
                    <div className="flex items-center justify-between">
                      <span className="font-semibold text-cyan-400">{type}</span>
                      {note && <span className="text-[10px] text-slate-500">{note}</span>}
                    </div>
                    <code className="text-slate-200 break-all">{value}</code>
                  </div>
                );
              })}
            </div>
          </div>
        )}

        {/* Defensive Recommendations */}
        <div className="p-4 rounded-xl bg-cyan-950/30 border border-cyan-800/40 space-y-2 text-xs">
          <h4 className="font-bold text-cyan-300 flex items-center gap-1.5">
            <svg className="w-4 h-4 text-cyan-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
            </svg>
            <span>ScamShield Citizen Advisory</span>
          </h4>
          <ul className="list-disc list-inside space-y-1 text-slate-300">
            <li>Never click links received via SMS/WhatsApp claiming account block or KYC expiry.</li>
            <li>Police, CBI, ED, and RBI never conduct interrogations or digital arrests via video calls.</li>
            <li>Report suspicious cyber incidents to 1930 or file on cybercrime.gov.in.</li>
          </ul>
        </div>
      </div>

      {/* Community Discussion & Verification Comments */}
      <div className="p-6 rounded-2xl bg-slate-900 border border-slate-800 space-y-6">
        <h3 className="text-lg font-bold text-white tracking-tight">
          Community Verification & Intel ({comments.length})
        </h3>

        {/* Comment Form */}
        <form onSubmit={handleAddComment} className="space-y-3">
          <textarea
            rows={3}
            value={newComment}
            onChange={(e) => setNewComment(e.target.value)}
            placeholder="Share corroborating evidence, scammer variations, or verification details..."
            className="w-full p-3 rounded-xl bg-slate-950 border border-slate-800 text-white placeholder-slate-500 text-xs sm:text-sm focus:outline-none focus:border-cyan-500"
          />
          <div className="flex justify-between items-center">
            <span className="text-[11px] text-slate-500">Comments are automatically checked for PII redaction.</span>
            <button
              type="submit"
              disabled={submittingComment || !newComment.trim()}
              className="px-4 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 disabled:opacity-50 text-white font-semibold text-xs transition-colors"
            >
              {submittingComment ? 'Posting...' : 'Post Intel'}
            </button>
          </div>
        </form>

        {/* Comments List */}
        <div className="space-y-3 pt-2">
          {comments.length === 0 ? (
            <p className="text-xs text-slate-500 py-4 text-center">No community intel posted yet. Be the first to verify.</p>
          ) : (
            comments.map((c) => (
              <div key={c.id} className="p-4 rounded-xl bg-slate-950 border border-slate-800/80 space-y-1 text-xs">
                <div className="flex items-center justify-between text-slate-400">
                  <span className="font-bold text-slate-200">
                    {c.author_username} <span className="text-[10px] text-slate-500 font-normal">(Trust {c.author_trust_score})</span>
                  </span>
                  <span className="text-[10px] text-slate-500">{new Date(c.created_at).toLocaleString()}</span>
                </div>
                <p className="text-slate-300 text-xs sm:text-sm pt-1">{c.content}</p>
              </div>
            ))
          )}
        </div>
      </div>
    </div>
  );
}
