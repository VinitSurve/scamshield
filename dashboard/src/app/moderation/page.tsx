'use client';

import { useEffect, useState } from 'react';

export default function ModerationPage() {
  const [pendingPosts, setPendingPosts] = useState<any[]>([]);
  const [benchmarkCandidates, setBenchmarkCandidates] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [errorMsg, setErrorMsg] = useState('');

  const fetchModerationData = async () => {
    setLoading(true);
    try {
      const res = await fetch('/api/moderation');
      const data = await res.json();
      if (data.success) {
        setPendingPosts(data.pendingPosts || []);
        setBenchmarkCandidates(data.benchmarkCandidates || []);
      } else {
        setErrorMsg(data.error || 'Moderator access required.');
      }
    } catch {
      setErrorMsg('Error loading moderation queue');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchModerationData();
  }, []);

  const handleAction = async (actionType: string, targetType: string, targetId: string) => {
    try {
      const res = await fetch('/api/moderation', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ actionType, targetType, targetId }),
      });
      const data = await res.json();
      if (data.success) {
        fetchModerationData();
      } else {
        alert(data.error || 'Action failed');
      }
    } catch {
      alert('Error communicating with moderation API');
    }
  };

  if (loading) {
    return (
      <div className="py-20 text-center text-slate-500 text-sm">
        <svg className="animate-spin h-6 w-6 text-cyan-500 mx-auto mb-2" viewBox="0 0 24 24" fill="none">
          <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
          <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8v8H4z" />
        </svg>
        Loading moderation queue...
      </div>
    );
  }

  if (errorMsg) {
    return (
      <div className="max-w-md mx-auto py-16 text-center space-y-4">
        <div className="p-4 rounded-xl bg-rose-950/80 border border-rose-800 text-rose-300 text-sm">
          {errorMsg}
        </div>
        <p className="text-xs text-slate-400">
          Sign in as an administrator or moderator account to access this terminal.
        </p>
      </div>
    );
  }

  return (
    <div className="space-y-8">
      <div>
        <h1 className="text-2xl sm:text-3xl font-bold text-white tracking-tight">
          Moderation Portal & Dataset Curation Pipeline
        </h1>
        <p className="text-sm text-slate-400">
          Review community threat reports, verify legitimacy, disarm false positives, and promote verified samples to ML benchmark datasets.
        </p>
      </div>

      {/* Pending Community Submissions */}
      <div className="p-6 rounded-2xl bg-slate-900 border border-slate-800 space-y-4">
        <h2 className="text-base font-bold text-white tracking-tight flex items-center justify-between">
          <span>Pending Threat Verifications ({pendingPosts.length})</span>
        </h2>

        {pendingPosts.length === 0 ? (
          <p className="text-xs text-slate-500 py-4 text-center">No reports awaiting moderation.</p>
        ) : (
          <div className="space-y-3">
            {pendingPosts.map((post) => (
              <div
                key={post.id}
                className="p-4 rounded-xl bg-slate-950 border border-slate-800 space-y-3"
              >
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <div className="flex items-center gap-2">
                    <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-amber-950 text-amber-300 border border-amber-800">
                      {post.severity}
                    </span>
                    <span className="font-semibold text-xs text-white">{post.title}</span>
                  </div>
                  <span className="text-[10px] text-slate-500">
                    By {post.author_username} • {new Date(post.created_at).toLocaleDateString()}
                  </span>
                </div>

                <div className="p-2.5 rounded bg-slate-900 text-slate-300 font-mono text-xs break-all">
                  {post.content}
                </div>

                {/* Moderator Actions */}
                <div className="flex flex-wrap gap-2 pt-1">
                  <button
                    onClick={() => handleAction('VERIFY_POST', 'post', post.id)}
                    className="px-3 py-1.5 rounded bg-emerald-600 hover:bg-emerald-500 text-white font-semibold text-xs transition-colors"
                  >
                    ✓ Verify Threat
                  </button>
                  <button
                    onClick={() => handleAction('FLAG_FALSE_REPORT', 'post', post.id)}
                    className="px-3 py-1.5 rounded bg-amber-600 hover:bg-amber-500 text-white font-semibold text-xs transition-colors"
                  >
                    Flag False Report
                  </button>
                  <button
                    onClick={() => handleAction('RESOLVE_POST', 'post', post.id)}
                    className="px-3 py-1.5 rounded bg-slate-800 hover:bg-slate-700 text-slate-200 font-semibold text-xs transition-colors"
                  >
                    Mark Resolved
                  </button>
                  <button
                    onClick={() => handleAction('DELETE_POST', 'post', post.id)}
                    className="px-3 py-1.5 rounded bg-rose-950 hover:bg-rose-900 text-rose-300 border border-rose-800 font-semibold text-xs transition-colors"
                  >
                    Delete Post
                  </button>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Benchmark Curation Pipeline */}
      <div className="p-6 rounded-2xl bg-slate-900 border border-slate-800 space-y-4">
        <div className="flex items-center justify-between">
          <div>
            <h2 className="text-base font-bold text-white tracking-tight">
              ML Lab Dataset Curation Pipeline ({benchmarkCandidates.length})
            </h2>
            <p className="text-xs text-slate-400">Curate citizen reports to prevent synthetic leakage and enhance Dataset v3</p>
          </div>
        </div>

        {benchmarkCandidates.length === 0 ? (
          <p className="text-xs text-slate-500 py-4 text-center">No benchmark contributions in queue.</p>
        ) : (
          <div className="space-y-3">
            {benchmarkCandidates.map((bench) => (
              <div
                key={bench.id}
                className="p-4 rounded-xl bg-slate-950 border border-slate-800 space-y-2 text-xs"
              >
                <div className="flex items-center justify-between">
                  <span className="font-semibold text-cyan-400">
                    Category: {bench.category} • Label: {bench.suggested_label} ({bench.language})
                  </span>
                  <span className="text-[10px] text-slate-500">By {bench.contributor_username}</span>
                </div>
                <div className="p-2.5 rounded bg-slate-900 text-slate-300 font-mono text-xs break-all">
                  {bench.content}
                </div>
                <div className="flex gap-2 pt-1">
                  <button
                    onClick={() => handleAction('APPROVE_BENCHMARK', 'benchmark', bench.id)}
                    className="px-3 py-1 rounded bg-cyan-600 hover:bg-cyan-500 text-white font-semibold text-xs transition-colors"
                  >
                    Promote to Benchmark Dataset
                  </button>
                  <button
                    onClick={() => handleAction('REJECT_BENCHMARK', 'benchmark', bench.id)}
                    className="px-3 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 font-semibold text-xs transition-colors"
                  >
                    Reject
                  </button>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
