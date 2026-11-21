'use client';

import { useEffect, useState } from 'react';

export default function TestingLabPage() {
  const [profile, setProfile] = useState('STANDARD');
  const [modelName, setModelName] = useState('ScamShield-Ensemble-v3');
  const [running, setRunning] = useState(false);
  const [activeRun, setActiveRun] = useState<any>(null);
  const [runsHistory, setRunsHistory] = useState<any[]>([]);
  const [filterResult, setFilterResult] = useState<'ALL' | 'PASSED' | 'FAILED'>('ALL');

  const fetchPastRuns = async () => {
    try {
      const res = await fetch('/api/testing/matrix');
      const data = await res.json();
      if (data.success && data.runs?.length > 0) {
        setRunsHistory(data.runs);
        // Load latest run details if none selected
        if (!activeRun) {
          loadRunDetails(data.runs[0].id);
        }
      }
    } catch {
      // Handled
    }
  };

  const loadRunDetails = async (id: string) => {
    try {
      const res = await fetch(`/api/testing/runs/${id}`);
      const data = await res.json();
      if (data.success) {
        setActiveRun({
          ...data.run,
          metrics: data.run.metrics,
          details: data.testCases,
        });
      }
    } catch {
      // Handled
    }
  };

  useEffect(() => {
    fetchPastRuns();
  }, []);

  const handleRunMatrix = async () => {
    setRunning(true);
    try {
      const res = await fetch('/api/testing/matrix', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ profile, modelName }),
      });
      const data = await res.json();
      if (data.success) {
        setActiveRun(data.summary);
        fetchPastRuns();
      } else {
        alert(data.error || 'Matrix execution failed');
      }
    } catch {
      alert('Error connecting to testing engine');
    } finally {
      setRunning(false);
    }
  };

  const filteredTestCases = (activeRun?.details || []).filter((tc: any) => {
    if (filterResult === 'PASSED') return tc.passed === 1 || tc.passed === true;
    if (filterResult === 'FAILED') return tc.passed === 0 || tc.passed === false;
    return true;
  });

  return (
    <div className="space-y-8">
      {/* Title */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl sm:text-3xl font-bold text-white tracking-tight">
            ScamShield Adversarial Testing Lab & Matrix
          </h1>
          <p className="text-sm text-slate-400">
            Systematic robustness validation across 18 adversarial attack vectors, multiple Indian languages, and real-world scam typologies.
          </p>
        </div>

        {/* Trigger Matrix Test Control */}
        <div className="flex flex-wrap items-center gap-2">
          <select
            value={profile}
            onChange={(e) => setProfile(e.target.value)}
            disabled={running}
            className="px-3 py-2 rounded-lg bg-slate-900 border border-slate-700 text-slate-200 text-xs focus:outline-none"
          >
            <option value="QUICK">Profile: QUICK (12 cases)</option>
            <option value="STANDARD">Profile: STANDARD (Baseline + Representative)</option>
            <option value="ADVERSARIAL">Profile: ADVERSARIAL (All 18 Attacks)</option>
            <option value="LANGUAGE">Profile: LANGUAGE (Cross-Lingual)</option>
            <option value="DOCUMENT">Profile: DOCUMENT (Document Parser)</option>
          </select>

          <button
            onClick={handleRunMatrix}
            disabled={running}
            className="px-4 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 font-bold text-white text-xs shadow-md shadow-cyan-600/30 transition-all flex items-center gap-2 disabled:opacity-50"
          >
            {running ? (
              <>
                <svg className="animate-spin h-3.5 w-3.5 text-white" viewBox="0 0 24 24" fill="none">
                  <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                  <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8v8H4z" />
                </svg>
                <span>Running Matrix...</span>
              </>
            ) : (
              <>
                <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M14.752 11.168l-3.197-2.132A1 1 0 0010 9.87v4.263a1 1 0 001.555.832l3.197-2.132a1 1 0 000-1.664z" />
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                </svg>
                <span>Execute Matrix Run</span>
              </>
            )}
          </button>
        </div>
      </div>

      {/* Aggregate Scorecard */}
      {activeRun ? (
        <div className="space-y-6">
          <div className="p-6 rounded-2xl bg-slate-900 border border-slate-800 space-y-4">
            <div className="flex flex-wrap items-center justify-between gap-4 border-b border-slate-800 pb-4">
              <div className="flex items-center gap-3">
                <span className="font-mono text-sm font-bold text-cyan-400">
                  {activeRun.run_id || activeRun.runId}
                </span>
                <span className="px-2 py-0.5 rounded text-[11px] font-semibold bg-slate-800 text-slate-300">
                  Profile: {activeRun.test_profile || activeRun.testProfile}
                </span>
                <span className="px-2 py-0.5 rounded text-[11px] font-semibold bg-slate-800 text-slate-300">
                  Model: {activeRun.model_name || activeRun.modelName}
                </span>
              </div>
              <span
                className={`px-2.5 py-1 rounded text-xs font-bold ${
                  (activeRun.status || '').toUpperCase() === 'PASSED'
                    ? 'bg-emerald-950 text-emerald-300 border border-emerald-800'
                    : 'bg-rose-950 text-rose-300 border border-rose-800'
                }`}
              >
                {activeRun.status}
              </span>
            </div>

            {/* Metrics Cards Grid */}
            <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-6 gap-3">
              <div className="p-3 rounded-xl bg-slate-950 border border-slate-800/80 text-center">
                <span className="text-[10px] text-slate-500 uppercase font-semibold">Total Samples (N)</span>
                <div className="text-xl font-bold text-white mt-1">
                  {activeRun.sample_count || activeRun.sampleCount}
                </div>
              </div>

              <div className="p-3 rounded-xl bg-slate-950 border border-slate-800/80 text-center">
                <span className="text-[10px] text-slate-500 uppercase font-semibold">Accuracy</span>
                <div className="text-xl font-bold text-cyan-400 mt-1">
                  {activeRun.accuracy}%
                </div>
              </div>

              <div className="p-3 rounded-xl bg-slate-950 border border-slate-800/80 text-center">
                <span className="text-[10px] text-slate-500 uppercase font-semibold">Precision</span>
                <div className="text-xl font-bold text-emerald-400 mt-1">
                  {activeRun.precision}%
                </div>
              </div>

              <div className="p-3 rounded-xl bg-slate-950 border border-slate-800/80 text-center">
                <span className="text-[10px] text-slate-500 uppercase font-semibold">Recall</span>
                <div className="text-xl font-bold text-emerald-400 mt-1">
                  {activeRun.recall}%
                </div>
              </div>

              <div className="p-3 rounded-xl bg-slate-950 border border-slate-800/80 text-center">
                <span className="text-[10px] text-slate-500 uppercase font-semibold">F1-Score</span>
                <div className="text-xl font-bold text-cyan-400 mt-1">
                  {activeRun.f1_score || activeRun.f1Score}%
                </div>
              </div>

              <div className="p-3 rounded-xl bg-slate-950 border border-slate-800/80 text-center">
                <span className="text-[10px] text-slate-500 uppercase font-semibold">False Positive Rate</span>
                <div className="text-xl font-bold text-amber-400 mt-1">
                  {activeRun.fpr}%
                </div>
              </div>
            </div>
          </div>

          {/* Breakdown Tables (Attacks & Categories) */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {/* 18 Adversarial Attacks Breakdown */}
            <div className="p-5 rounded-2xl bg-slate-900 border border-slate-800 space-y-3">
              <h3 className="text-sm font-bold text-white tracking-tight flex items-center justify-between">
                <span>18 Adversarial Attack Transformations</span>
                <span className="text-[11px] text-slate-500 font-normal">Robustness %</span>
              </h3>
              <div className="max-h-60 overflow-y-auto space-y-1.5 pr-1">
                {activeRun.resultsByAttack || activeRun.metrics?.byAttack ? (
                  Object.entries(activeRun.resultsByAttack || activeRun.metrics.byAttack).map(
                    ([attack, val]: any) => (
                      <div
                        key={attack}
                        className="flex items-center justify-between text-xs p-2 rounded bg-slate-950/80 border border-slate-800/60"
                      >
                        <span className="font-mono text-slate-300">{attack}</span>
                        <div className="flex items-center gap-2">
                          <span className="text-slate-500 text-[10px]">({val.passed}/{val.total})</span>
                          <span className={`font-bold ${val.accuracy >= 90 ? 'text-emerald-400' : val.accuracy >= 75 ? 'text-amber-400' : 'text-rose-400'}`}>
                            {val.accuracy}%
                          </span>
                        </div>
                      </div>
                    )
                  )
                ) : (
                  <p className="text-xs text-slate-500 py-3 text-center">Attack breakdown available for standard & adversarial profiles.</p>
                )}
              </div>
            </div>

            {/* Category Breakdown */}
            <div className="p-5 rounded-2xl bg-slate-900 border border-slate-800 space-y-3">
              <h3 className="text-sm font-bold text-white tracking-tight flex items-center justify-between">
                <span>Threat Category Breakdown</span>
                <span className="text-[11px] text-slate-500 font-normal">Accuracy %</span>
              </h3>
              <div className="max-h-60 overflow-y-auto space-y-1.5 pr-1">
                {activeRun.resultsByCategory || activeRun.metrics?.byCategory ? (
                  Object.entries(activeRun.resultsByCategory || activeRun.metrics.byCategory).map(
                    ([cat, val]: any) => (
                      <div
                        key={cat}
                        className="flex items-center justify-between text-xs p-2 rounded bg-slate-950/80 border border-slate-800/60"
                      >
                        <span className="text-slate-300 font-medium">{cat.replace(/_/g, ' ')}</span>
                        <div className="flex items-center gap-2">
                          <span className="text-slate-500 text-[10px]">({val.passed}/{val.total})</span>
                          <span className={`font-bold ${val.accuracy >= 90 ? 'text-emerald-400' : 'text-amber-400'}`}>
                            {val.accuracy}%
                          </span>
                        </div>
                      </div>
                    )
                  )
                ) : (
                  <p className="text-xs text-slate-500 py-3 text-center">Category breakdown data loading...</p>
                )}
              </div>
            </div>
          </div>

          {/* Test Cases Table with Passed/Failed filter */}
          <div className="p-6 rounded-2xl bg-slate-900 border border-slate-800 space-y-4">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
              <h3 className="text-base font-bold text-white tracking-tight">
                Evaluated Test Cases ({filteredTestCases.length})
              </h3>
              <div className="flex items-center gap-1 bg-slate-950 p-1 rounded-lg border border-slate-800 self-start sm:self-auto">
                <button
                  onClick={() => setFilterResult('ALL')}
                  className={`px-2.5 py-1 rounded text-xs font-semibold ${
                    filterResult === 'ALL' ? 'bg-cyan-600 text-white' : 'text-slate-400 hover:text-white'
                  }`}
                >
                  All
                </button>
                <button
                  onClick={() => setFilterResult('PASSED')}
                  className={`px-2.5 py-1 rounded text-xs font-semibold ${
                    filterResult === 'PASSED' ? 'bg-emerald-600 text-white' : 'text-slate-400 hover:text-white'
                  }`}
                >
                  Passed
                </button>
                <button
                  onClick={() => setFilterResult('FAILED')}
                  className={`px-2.5 py-1 rounded text-xs font-semibold ${
                    filterResult === 'FAILED' ? 'bg-rose-600 text-white' : 'text-slate-400 hover:text-white'
                  }`}
                >
                  Failed
                </button>
              </div>
            </div>

            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs text-slate-300">
                <thead className="bg-slate-950 text-slate-400 uppercase text-[10px] tracking-wider border-b border-slate-800">
                  <tr>
                    <th className="py-2.5 px-3">Status</th>
                    <th className="py-2.5 px-3">Content / Payload</th>
                    <th className="py-2.5 px-3">Category</th>
                    <th className="py-2.5 px-3">Attack Applied</th>
                    <th className="py-2.5 px-3">Expected</th>
                    <th className="py-2.5 px-3">Predicted</th>
                    <th className="py-2.5 px-3 text-right">Latency</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60">
                  {filteredTestCases.map((tc: any, i: number) => {
                    const isPassed = tc.passed === 1 || tc.passed === true;
                    return (
                      <tr key={i} className="hover:bg-slate-800/40">
                        <td className="py-2.5 px-3">
                          <span
                            className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                              isPassed
                                ? 'bg-emerald-950 text-emerald-300 border border-emerald-800'
                                : 'bg-rose-950 text-rose-300 border border-rose-800'
                            }`}
                          >
                            {isPassed ? 'PASS' : 'FAIL'}
                          </span>
                        </td>
                        <td className="py-2.5 px-3 font-mono text-[11px] max-w-xs truncate" title={tc.content}>
                          {tc.content}
                        </td>
                        <td className="py-2.5 px-3 font-medium text-slate-400">
                          {tc.category?.replace(/_/g, ' ')}
                        </td>
                        <td className="py-2.5 px-3 font-mono text-cyan-400">
                          {tc.attack_type || tc.attackType || 'NONE'}
                        </td>
                        <td className="py-2.5 px-3 text-slate-300">{tc.expected_label || tc.expectedLabel}</td>
                        <td className="py-2.5 px-3 font-bold text-slate-200">{tc.predicted_label || tc.predictedLabel}</td>
                        <td className="py-2.5 px-3 text-right text-slate-500 font-mono">
                          {tc.latency_ms || tc.latencyMs}ms
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      ) : (
        <div className="p-12 text-center bg-slate-900 rounded-2xl border border-slate-800 space-y-3">
          <p className="text-slate-400 text-sm">No test matrix runs found. Click &quot;Execute Matrix Run&quot; above to validate model robustness.</p>
        </div>
      )}

      {/* Historical Test Matrix Runs */}
      {runsHistory.length > 0 && (
        <div className="p-6 rounded-2xl bg-slate-900 border border-slate-800 space-y-4">
          <h3 className="text-sm font-bold text-white tracking-tight uppercase">
            Test Matrix Execution History
          </h3>
          <div className="divide-y divide-slate-800/80">
            {runsHistory.map((run) => (
              <div
                key={run.id}
                onClick={() => loadRunDetails(run.id)}
                className="py-3 flex flex-wrap items-center justify-between gap-3 cursor-pointer hover:bg-slate-800/40 px-2 rounded-lg transition-colors"
              >
                <div className="flex items-center gap-3 text-xs">
                  <span className="font-mono text-cyan-400 font-bold">{run.run_id}</span>
                  <span className="text-slate-400">{run.test_profile}</span>
                  <span className="text-slate-500">{new Date(run.created_at).toLocaleString()}</span>
                </div>
                <div className="flex items-center gap-4 text-xs">
                  <span className="text-slate-300">Accuracy: <strong>{run.accuracy}%</strong></span>
                  <span className="text-slate-300">F1: <strong>{run.f1_score}%</strong></span>
                  <span
                    className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                      run.status === 'PASSED'
                        ? 'bg-emerald-950 text-emerald-400'
                        : 'bg-rose-950 text-rose-400'
                    }`}
                  >
                    {run.status}
                  </span>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
