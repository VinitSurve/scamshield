'use client';

import { useEffect, useState } from 'react';
import Link from 'next/link';

export default function CommunityFeedPage() {
  const [posts, setPosts] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [category, setCategory] = useState('ALL');
  const [severity, setSeverity] = useState('ALL');
  const [status, setStatus] = useState('ALL');
  const [search, setSearch] = useState('');

  const fetchPosts = async () => {
    setLoading(true);
    try {
      const params = new URLSearchParams();
      if (category !== 'ALL') params.set('category', category);
      if (severity !== 'ALL') params.set('severity', severity);
      if (status !== 'ALL') params.set('status', status);
      if (search.trim()) params.set('search', search.trim());

      const res = await fetch(`/api/posts?${params.toString()}`);
      const data = await res.json();
      if (data.success) {
        setPosts(data.posts || []);
      }
    } catch {
      // Handled
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchPosts();
  }, [category, severity, status]);

  const handleSearchSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    fetchPosts();
  };

  const handleVote = async (postId: string, voteType: 'UP' | 'DOWN', e: React.MouseEvent) => {
    e.preventDefault();
    e.stopPropagation();

    try {
      const res = await fetch(`/api/posts/${postId}/vote`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ voteType }),
      });
      const data = await res.json();
      if (data.success) {
        // Optimistically update
        setPosts((prev) =>
          prev.map((p) => {
            if (p.id === postId) {
              const delta = voteType === 'UP' ? 1 : -1;
              return { ...p, upvotes: Math.max(0, p.upvotes + delta) };
            }
            return p;
          })
        );
      } else {
        alert(data.error || 'Please login to vote');
      }
    } catch {
      // Handled
    }
  };

  const categories = [
    { id: 'ALL', label: 'All Threats' },
    { id: 'BANKING_KYC', label: 'Banking / KYC' },
    { id: 'ELECTRICITY', label: 'Electricity Cutoff' },
    { id: 'DIGITAL_ARREST', label: 'Digital Arrest / CBI' },
    { id: 'JOB_OFFER', label: 'Job / Task Scam' },
    { id: 'UPI_FRAUD', label: 'UPI / Refund Trap' },
    { id: 'PHISHING_URL', label: 'Phishing URLs' },
  ];

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl sm:text-3xl font-bold text-white tracking-tight">
            Community Threat Intelligence Feed
          </h1>
          <p className="text-sm text-slate-400">
            Citizen-reported scam messages, links, and documents verified with automated ScamShield AI analysis.
          </p>
        </div>
        <Link
          href="/report"
          className="inline-flex items-center justify-center gap-2 px-4 py-2.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 font-semibold text-white text-sm shadow-md shadow-cyan-600/30 transition-all self-start sm:self-auto"
        >
          <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 4v16m8-8H4" />
          </svg>
          <span>Report New Scam</span>
        </Link>
      </div>

      {/* Filter Tabs & Search */}
      <div className="space-y-3">
        {/* Category Pills */}
        <div className="flex items-center gap-2 overflow-x-auto no-scrollbar pb-1">
          {categories.map((c) => (
            <button
              key={c.id}
              onClick={() => setCategory(c.id)}
              className={`px-3 py-1.5 rounded-lg text-xs font-semibold whitespace-nowrap transition-all ${
                category === c.id
                  ? 'bg-cyan-500 text-slate-950 shadow-md shadow-cyan-500/20'
                  : 'bg-slate-900 text-slate-400 hover:text-white border border-slate-800'
              }`}
            >
              {c.label}
            </button>
          ))}
        </div>

        {/* Search & Severity Dropdown */}
        <div className="flex flex-col sm:flex-row gap-3">
          <form onSubmit={handleSearchSubmit} className="flex-1">
            <input
              type="text"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="Search by keywords, URLs, phone numbers, or sender..."
              className="w-full px-4 py-2 rounded-lg bg-slate-900 border border-slate-800 text-white placeholder-slate-500 text-sm focus:outline-none focus:border-cyan-500"
            />
          </form>

          <div className="flex gap-2">
            <select
              value={severity}
              onChange={(e) => setSeverity(e.target.value)}
              className="px-3 py-2 rounded-lg bg-slate-900 border border-slate-800 text-slate-300 text-xs focus:outline-none"
            >
              <option value="ALL">All Severities</option>
              <option value="CRITICAL">Critical</option>
              <option value="HIGH">High</option>
              <option value="SUSPICIOUS">Suspicious</option>
              <option value="SAFE">Safe / False Positive</option>
            </select>

            <select
              value={status}
              onChange={(e) => setStatus(e.target.value)}
              className="px-3 py-2 rounded-lg bg-slate-900 border border-slate-800 text-slate-300 text-xs focus:outline-none"
            >
              <option value="ALL">All Statuses</option>
              <option value="VERIFIED">Verified</option>
              <option value="COMMUNITY_SUPPORTED">Community Supported</option>
              <option value="UNDER_REVIEW">Under Review</option>
              <option value="UNVERIFIED">Unverified</option>
            </select>
          </div>
        </div>
      </div>

      {/* Posts List */}
      {loading ? (
        <div className="text-center py-16 text-slate-500 text-sm">
          <svg className="animate-spin h-6 w-6 text-cyan-500 mx-auto mb-2" viewBox="0 0 24 24" fill="none">
            <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
            <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8v8H4z" />
          </svg>
          Loading intelligence feed...
        </div>
      ) : posts.length === 0 ? (
        <div className="text-center py-16 bg-slate-900/40 rounded-xl border border-slate-800 p-8 space-y-3">
          <p className="text-slate-400 text-sm">No scam reports match the selected filters.</p>
          <button
            onClick={() => {
              setCategory('ALL');
              setSeverity('ALL');
              setStatus('ALL');
              setSearch('');
            }}
            className="text-xs text-cyan-400 hover:underline"
          >
            Reset Filters
          </button>
        </div>
      ) : (
        <div className="space-y-4">
          {posts.map((post) => (
            <div
              key={post.id}
              className="p-5 rounded-xl bg-slate-900/70 border border-slate-800 hover:border-slate-700 transition-all space-y-3"
            >
              <div className="flex items-start justify-between gap-4">
                <div className="space-y-1">
                  <div className="flex flex-wrap items-center gap-2">
                    {/* Severity Badge */}
                    <span
                      className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                        post.severity === 'CRITICAL'
                          ? 'bg-rose-950 text-rose-300 border border-rose-800'
                          : post.severity === 'HIGH'
                          ? 'bg-orange-950 text-orange-300 border border-orange-800'
                          : post.severity === 'SUSPICIOUS'
                          ? 'bg-amber-950 text-amber-300 border border-amber-800'
                          : 'bg-emerald-950 text-emerald-300 border border-emerald-800'
                      }`}
                    >
                      {post.severity}
                    </span>

                    {/* Verification Status */}
                    <span
                      className={`px-2 py-0.5 rounded text-[10px] font-semibold ${
                        post.verification_status === 'VERIFIED'
                          ? 'bg-emerald-950 text-emerald-300 border border-emerald-800'
                          : post.verification_status === 'COMMUNITY_SUPPORTED'
                          ? 'bg-cyan-950 text-cyan-300 border border-cyan-800'
                          : 'bg-slate-800 text-slate-300 border border-slate-700'
                      }`}
                    >
                      {post.verification_status.replace(/_/g, ' ')}
                    </span>

                    <span className="px-2 py-0.5 rounded text-[10px] font-medium bg-slate-800/80 text-slate-400">
                      {post.category.replace(/_/g, ' ')}
                    </span>

                    <span className="text-[11px] text-slate-500">
                      Reported by <strong className="text-slate-400">{post.author_username}</strong> (Trust {post.author_trust_score}) • {new Date(post.created_at).toLocaleDateString()}
                    </span>
                  </div>

                  <Link href={`/community/${post.id}`} className="block">
                    <h2 className="text-base font-semibold text-white hover:text-cyan-400 transition-colors">
                      {post.title}
                    </h2>
                  </Link>
                </div>

                {/* Vote Counter */}
                <div className="flex flex-col items-center gap-1 shrink-0 bg-slate-950/60 p-1.5 rounded-lg border border-slate-800">
                  <button
                    onClick={(e) => handleVote(post.id, 'UP', e)}
                    className="p-1 hover:text-cyan-400 text-slate-400 transition-colors"
                    title="Upvote verified threat"
                  >
                    <svg className="w-4 h-4" fill="currentColor" viewBox="0 0 20 20">
                      <path fillRule="evenodd" d="M14.707 12.707a1 1 0 01-1.414 0L10 9.414l-3.293 3.293a1 1 0 01-1.414-1.414l4-4a1 1 0 011.414 0l4 4a1 1 0 010 1.414z" clipRule="evenodd" />
                    </svg>
                  </button>
                  <span className="text-xs font-bold text-white">{post.upvotes}</span>
                </div>
              </div>

              {/* Redacted Content Snippet */}
              <div className="p-3 rounded-lg bg-slate-950 border border-slate-800/80 font-mono text-xs text-slate-300 break-words">
                {post.content}
              </div>

              {/* Threat Indicators & Details */}
              <div className="flex flex-wrap items-center justify-between gap-3 pt-1 text-xs">
                <div className="flex flex-wrap items-center gap-1.5">
                  <span className="text-slate-500">Platform: {post.platform}</span>
                  <span className="text-slate-700">•</span>
                  <span className="text-slate-500">Language: {post.language.toUpperCase()}</span>
                </div>
                <Link
                  href={`/community/${post.id}`}
                  className="font-medium text-cyan-400 hover:text-cyan-300 hover:underline"
                >
                  View Indicators & Recommendations →
                </Link>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
