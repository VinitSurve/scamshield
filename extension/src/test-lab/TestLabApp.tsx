import React, { useState } from 'react';
import {
  Play,
  RotateCcw,
  CheckCircle,
  XCircle,
  AlertTriangle,
  Clock,
  Shield,
  ExternalLink,
  ChevronDown,
  ChevronRight,
  Info,
} from 'lucide-react';
import { CONTROLLED_TEST_CASES } from './test-cases';
import { TestCase, TestResult, TestExecutionStatus } from './types';
import { TestRunner } from './test-runner';

export const TestLabApp: React.FC = () => {
  const [testCases] = useState<TestCase[]>(CONTROLLED_TEST_CASES);
  const [results, setResults] = useState<Record<string, TestResult>>({});
  const [isRunningAll, setIsRunningAll] = useState(false);
  const [activeTestId, setActiveTestId] = useState<string | null>(null);
  const [expandedCards, setExpandedCards] = useState<Record<string, boolean>>({});
  const [filter, setFilter] = useState<'ALL' | 'PASS' | 'FAIL' | 'WARNING' | 'IDLE'>('ALL');

  const totalCount = testCases.length;
  const executedCount = Object.keys(results).length;
  const passedCount = Object.values(results).filter((r) => r.status === 'PASS').length;
  const failedCount = Object.values(results).filter((r) => r.status === 'FAIL').length;
  const warningCount = Object.values(results).filter((r) => r.status === 'WARNING').length;
  const pendingCount = totalCount - executedCount;

  const handleRunAll = async () => {
    setIsRunningAll(true);
    try {
      await TestRunner.runAllTests(testCases, (_completed, _total, latestResult) => {
        setResults((prev) => ({
          ...prev,
          [latestResult.testCase.id]: latestResult,
        }));
      });
    } catch (err) {
      console.error('Failed to run test suite:', err);
    } finally {
      setIsRunningAll(false);
      setActiveTestId(null);
    }
  };

  const handleRunSingle = async (testCase: TestCase) => {
    setActiveTestId(testCase.id);
    try {
      const result = await TestRunner.runSingleTest(testCase);
      setResults((prev) => ({
        ...prev,
        [testCase.id]: result,
      }));
    } catch (err) {
      console.error(`Failed to run test ${testCase.id}:`, err);
    } finally {
      setActiveTestId(null);
    }
  };

  const handleReset = () => {
    setResults({});
    setExpandedCards({});
  };

  const toggleExpand = (id: string) => {
    setExpandedCards((prev) => ({
      ...prev,
      [id]: !prev[id],
    }));
  };

  const filteredTestCases = testCases.filter((tc) => {
    const res = results[tc.id];
    const status: TestExecutionStatus = res ? res.status : 'IDLE';
    if (filter === 'ALL') return true;
    return status === filter;
  });

  const getStatusBadge = (status: TestExecutionStatus) => {
    switch (status) {
      case 'PASS':
        return (
          <span className="flex items-center space-x-1 px-2.5 py-1 rounded-full text-xs font-bold bg-emerald-950/60 text-emerald-400 border border-emerald-500/40">
            <CheckCircle className="w-3.5 h-3.5" />
            <span>PASS</span>
          </span>
        );
      case 'FAIL':
        return (
          <span className="flex items-center space-x-1 px-2.5 py-1 rounded-full text-xs font-bold bg-red-950/60 text-red-400 border border-red-500/40">
            <XCircle className="w-3.5 h-3.5" />
            <span>FAIL</span>
          </span>
        );
      case 'WARNING':
        return (
          <span className="flex items-center space-x-1 px-2.5 py-1 rounded-full text-xs font-bold bg-amber-950/60 text-amber-400 border border-amber-500/40">
            <AlertTriangle className="w-3.5 h-3.5" />
            <span>WARNING</span>
          </span>
        );
      case 'RUNNING':
        return (
          <span className="flex items-center space-x-1 px-2.5 py-1 rounded-full text-xs font-bold bg-cyan-950/60 text-cyan-400 border border-cyan-500/40 animate-pulse">
            <Clock className="w-3.5 h-3.5" />
            <span>RUNNING</span>
          </span>
        );
      default:
        return (
          <span className="flex items-center space-x-1 px-2.5 py-1 rounded-full text-xs font-medium bg-slate-800 text-slate-400 border border-slate-700">
            <span>NOT RUN</span>
          </span>
        );
    }
  };

  return (
    <div className="min-h-screen bg-shield-dark text-slate-100 py-8 px-6 font-sans">
      <div className="max-w-4xl mx-auto space-y-6">
        {/* Header Banner */}
        <div className="bg-shield-card border border-shield-border rounded-2xl p-6 shadow-xl flex flex-col md:flex-row md:items-center md:justify-between gap-4">
          <div className="flex items-start space-x-3.5">
            <div className="p-3 bg-shield-accent/20 rounded-2xl border border-shield-accent/30 text-shield-accent shrink-0">
              <Shield className="w-8 h-8" />
            </div>
            <div>
              <div className="flex items-center space-x-2">
                <h1 className="text-xl font-bold text-white tracking-tight">
                  ScamShield Security Test Lab
                </h1>
                <span className="text-[10px] px-2 py-0.5 rounded-full bg-cyan-950 text-cyan-400 border border-cyan-800 font-mono font-semibold">
                  DEVELOPER / HACKATHON
                </span>
              </div>
              <p className="text-xs text-slate-400 mt-1 leading-relaxed max-w-xl">
                Automated diagnostic suite exercising the actual ScamShield detection engine against controlled legitimate, brand-impersonating, offline threat, and redirect fixtures.
              </p>
            </div>
          </div>

          <div className="flex items-center space-x-2.5 shrink-0">
            <button
              onClick={handleReset}
              disabled={isRunningAll}
              className="flex items-center space-x-1.5 px-3.5 py-2.5 bg-shield-dark hover:bg-shield-cardHover text-slate-300 border border-shield-border rounded-xl text-xs font-semibold transition-all disabled:opacity-50"
            >
              <RotateCcw className="w-3.5 h-3.5" />
              <span>Reset</span>
            </button>
            <button
              onClick={handleRunAll}
              disabled={isRunningAll}
              className="flex items-center space-x-2 px-5 py-2.5 bg-shield-accent hover:bg-shield-accentHover text-slate-950 font-bold rounded-xl text-xs shadow-lg shadow-cyan-950/50 transition-all active:scale-[0.98] disabled:opacity-50"
            >
              <Play className={`w-3.5 h-3.5 fill-current ${isRunningAll ? 'animate-spin' : ''}`} />
              <span>{isRunningAll ? 'Running Test Suite...' : 'Run All Tests'}</span>
            </button>
          </div>
        </div>

        {/* Metrics Overview Bar */}
        <div className="grid grid-cols-2 sm:grid-cols-5 gap-3">
          <div className="bg-shield-card border border-shield-border rounded-xl p-3 text-center">
            <span className="text-[11px] font-medium text-slate-400 block">Total Tests</span>
            <span className="text-lg font-bold font-mono text-white">{totalCount}</span>
          </div>
          <div className="bg-shield-card border border-shield-border rounded-xl p-3 text-center">
            <span className="text-[11px] font-medium text-emerald-400 block">Passed</span>
            <span className="text-lg font-bold font-mono text-emerald-400">{passedCount}</span>
          </div>
          <div className="bg-shield-card border border-shield-border rounded-xl p-3 text-center">
            <span className="text-[11px] font-medium text-red-400 block">Failed</span>
            <span className="text-lg font-bold font-mono text-red-400">{failedCount}</span>
          </div>
          <div className="bg-shield-card border border-shield-border rounded-xl p-3 text-center">
            <span className="text-[11px] font-medium text-amber-400 block">Warnings</span>
            <span className="text-lg font-bold font-mono text-amber-400">{warningCount}</span>
          </div>
          <div className="bg-shield-card border border-shield-border rounded-xl p-3 text-center col-span-2 sm:col-span-1">
            <span className="text-[11px] font-medium text-slate-400 block">Pending</span>
            <span className="text-lg font-bold font-mono text-slate-400">{pendingCount}</span>
          </div>
        </div>

        {/* Filter Bar */}
        <div className="flex items-center space-x-2 border-b border-shield-border pb-3 overflow-x-auto text-xs">
          {[
            { id: 'ALL', label: `All Tests (${totalCount})` },
            { id: 'PASS', label: `Passed (${passedCount})` },
            { id: 'FAIL', label: `Failed (${failedCount})` },
            { id: 'WARNING', label: `Warnings (${warningCount})` },
            { id: 'IDLE', label: `Not Run (${pendingCount})` },
          ].map((tab) => (
            <button
              key={tab.id}
              onClick={() => setFilter(tab.id as any)}
              className={`px-3 py-1.5 rounded-lg font-medium transition-colors shrink-0 ${
                filter === tab.id
                  ? 'bg-shield-accent/20 text-shield-accent border border-shield-accent/40'
                  : 'text-slate-400 hover:text-white hover:bg-shield-card'
              }`}
            >
              {tab.label}
            </button>
          ))}
        </div>

        {/* Test Cards List */}
        <div className="space-y-3.5">
          {filteredTestCases.map((tc) => {
            const res = results[tc.id];
            const isExpanded = Boolean(expandedCards[tc.id]);
            const status: TestExecutionStatus =
              activeTestId === tc.id ? 'RUNNING' : res ? res.status : 'IDLE';

            return (
              <div
                key={tc.id}
                className="bg-shield-card border border-shield-border rounded-xl p-4.5 space-y-3 shadow-sm hover:border-slate-700 transition-colors"
              >
                {/* Header row */}
                <div className="flex items-start justify-between gap-3">
                  <div className="space-y-1">
                    <div className="flex items-center space-x-2">
                      {getStatusBadge(status)}
                      <span className="text-xs px-2 py-0.5 rounded bg-shield-dark text-slate-300 font-medium border border-shield-border">
                        {tc.categoryLabel}
                      </span>
                      <h3 className="text-sm font-bold text-white tracking-tight">{tc.title}</h3>
                    </div>

                    <div className="flex items-center space-x-1.5 text-xs text-slate-400 font-mono pt-0.5">
                      <ExternalLink className="w-3 h-3 text-slate-500 shrink-0" />
                      <span className="truncate max-w-md text-cyan-400">{tc.targetUrl}</span>
                    </div>
                  </div>

                  <button
                    onClick={() => handleRunSingle(tc)}
                    disabled={isRunningAll || activeTestId === tc.id}
                    className="flex items-center space-x-1 px-3 py-1.5 bg-shield-dark hover:bg-shield-cardHover text-slate-200 border border-shield-border rounded-lg text-xs font-semibold shrink-0 transition-colors disabled:opacity-50"
                  >
                    <Play className="w-3 h-3 fill-current" />
                    <span>Run</span>
                  </button>
                </div>

                <p className="text-xs text-slate-300 leading-relaxed">{tc.description}</p>

                {/* Expected vs Actual Table */}
                <div className="grid grid-cols-1 md:grid-cols-2 gap-2.5 pt-1 text-xs">
                  {/* Expected Box */}
                  <div className="bg-shield-dark/80 border border-shield-border/70 rounded-lg p-2.5 space-y-1">
                    <span className="text-[10px] uppercase font-mono tracking-wider text-slate-500 font-bold block">
                      Expected Contract
                    </span>
                    <div className="flex justify-between">
                      <span className="text-slate-400">Severity:</span>
                      <span className="font-mono font-semibold text-slate-200">
                        {Array.isArray(tc.expectedSeverity)
                          ? tc.expectedSeverity.join(' or ')
                          : tc.expectedSeverity}
                      </span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-slate-400">Category:</span>
                      <span className="font-mono text-slate-200">
                        {Array.isArray(tc.expectedCategory)
                          ? tc.expectedCategory.join(' or ')
                          : tc.expectedCategory}
                      </span>
                    </div>
                    {tc.expectedSource && (
                      <div className="flex justify-between">
                        <span className="text-slate-400">Source:</span>
                        <span className="font-mono text-slate-400">{tc.expectedSource}</span>
                      </div>
                    )}
                  </div>

                  {/* Actual Box */}
                  <div className="bg-shield-dark/80 border border-shield-border/70 rounded-lg p-2.5 space-y-1">
                    <span className="text-[10px] uppercase font-mono tracking-wider text-slate-500 font-bold block">
                      Actual ScamShield Verdict
                    </span>
                    {res && res.actualVerdict ? (
                      <>
                        <div className="flex justify-between">
                          <span className="text-slate-400">Severity:</span>
                          <span
                            className={`font-mono font-bold ${
                              res.actualVerdict.severity === 'SAFE'
                                ? 'text-emerald-400'
                                : res.actualVerdict.severity === 'SUSPICIOUS'
                                ? 'text-amber-400'
                                : res.actualVerdict.severity === 'CRITICAL' ||
                                  res.actualVerdict.severity === 'HIGH'
                                ? 'text-red-400'
                                : 'text-slate-300'
                            }`}
                          >
                            {res.actualVerdict.severity}
                          </span>
                        </div>
                        <div className="flex justify-between">
                          <span className="text-slate-400">Category / Score:</span>
                          <span className="font-mono text-slate-200">
                            {res.actualVerdict.category} ({Math.round(res.actualVerdict.riskScore * 100)}%)
                          </span>
                        </div>
                        <div className="flex justify-between">
                          <span className="text-slate-400">Source / Time:</span>
                          <span className="font-mono text-slate-400">
                            {res.actualVerdict.source} • {res.durationMs}ms
                          </span>
                        </div>
                      </>
                    ) : (
                      <p className="text-xs text-slate-500 italic pt-1">
                        Click "Run" or "Run All Tests" to evaluate.
                      </p>
                    )}
                  </div>
                </div>

                {/* Expandable Details Accordion */}
                {res && (
                  <div className="border-t border-shield-border/60 pt-2">
                    <button
                      onClick={() => toggleExpand(tc.id)}
                      className="flex items-center space-x-1 text-xs text-slate-400 hover:text-slate-200 transition-colors"
                    >
                      {isExpanded ? (
                        <ChevronDown className="w-3.5 h-3.5" />
                      ) : (
                        <ChevronRight className="w-3.5 h-3.5" />
                      )}
                      <span>
                        {isExpanded ? 'Hide Evidence & Diagnostics' : 'View Detected Evidence & Notes'}
                      </span>
                    </button>

                    {isExpanded && (
                      <div className="mt-2.5 p-3 bg-shield-dark rounded-lg space-y-2 text-xs border border-shield-border/60">
                        <div>
                          <span className="text-[10px] font-mono uppercase text-slate-400 font-bold block mb-1">
                            Engine Detection Evidence
                          </span>
                          {res.actualVerdict?.evidence && res.actualVerdict.evidence.length > 0 ? (
                            <ul className="space-y-1">
                              {res.actualVerdict.evidence.map((ev, i) => (
                                <li key={i} className="flex items-start space-x-1.5 text-slate-300">
                                  <span className="text-shield-accent mt-0.5">•</span>
                                  <span>{ev}</span>
                                </li>
                              ))}
                            </ul>
                          ) : (
                            <p className="text-slate-500 italic">No threat evidence reported.</p>
                          )}
                        </div>

                        {res.notes.length > 0 && (
                          <div className="border-t border-shield-border/40 pt-2">
                            <span className="text-[10px] font-mono uppercase text-slate-400 font-bold block mb-1">
                              Test Verification Notes
                            </span>
                            <ul className="space-y-0.5 text-slate-400 font-mono text-[11px]">
                              {res.notes.map((note, i) => (
                                <li key={i}>✓ {note}</li>
                              ))}
                            </ul>
                          </div>
                        )}
                      </div>
                    )}
                  </div>
                )}
              </div>
            );
          })}
        </div>

        {/* Footer Note */}
        <div className="bg-shield-card border border-shield-border rounded-xl p-4 text-xs text-slate-400 flex items-start space-x-2.5">
          <Info className="w-4 h-4 text-shield-accent shrink-0 mt-0.5" />
          <p className="leading-relaxed">
            <strong>Security Boundary Notice:</strong> All tests in this lab execute against ScamShield's real production evaluation pipeline (canonicalizer, homoglyph resolver, Tranco anchor lists, and heuristic algorithms). The scanner never initiates socket connections or downloads payloads from synthetic or malicious test domains.
          </p>
        </div>
      </div>
    </div>
  );
};
