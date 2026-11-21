import { TestCase, TestResult, TestExecutionStatus } from './types';
import { ReputationService } from '../services/reputation-service';
import { RedirectTracker } from '../background/redirect-tracker';
import { ReputationVerdict } from '../types/threat';

export class TestRunner {
  /**
   * Execute an individual test case against the actual production ScamShield engine
   */
  static async runSingleTest(testCase: TestCase): Promise<TestResult> {
    const startTime = performance.now();
    const notes: string[] = [];

    let actualVerdict: ReputationVerdict | undefined;
    let actualRedirectChain = undefined;

    try {
      if (testCase.isRedirectSimulation && testCase.simulationHops && testCase.simulationHops.length > 0) {
        // Multi-hop redirect simulation test
        const simTabId = 999000 + Math.floor(Math.random() * 1000);
        RedirectTracker.recordNavigationStart(simTabId, testCase.simulationHops[0]);

        for (let i = 1; i < testCase.simulationHops.length; i++) {
          RedirectTracker.recordHop(simTabId, testCase.simulationHops[i]);
        }

        actualRedirectChain = RedirectTracker.getChain(simTabId);
        const finalUrl = actualRedirectChain?.finalUrl || testCase.targetUrl;

        // Evaluate destination
        actualVerdict = await ReputationService.evaluateUrl(finalUrl, true);
        RedirectTracker.removeChain(simTabId);

        notes.push(`Simulated ${actualRedirectChain?.hops.length || 0} redirect hops`);
        if (actualRedirectChain?.isCrossDomain) {
          notes.push('Cross-domain redirection detected across hops');
        }
        if (actualRedirectChain?.hasSuspiciousHop) {
          notes.push('Suspicious or malicious destination hop intercepted');
        }
      } else {
        // Standard URL evaluation (skipCache: true to test engine logic cleanly)
        actualVerdict = await ReputationService.evaluateUrl(testCase.targetUrl, true);
      }
    } catch (err) {
      const durationMs = Math.round(performance.now() - startTime);
      return {
        testCase,
        status: 'FAIL',
        durationMs,
        notes: [`Engine error during test execution: ${err instanceof Error ? err.message : String(err)}`],
        executedAt: Date.now(),
      };
    }

    const durationMs = Math.round(performance.now() - startTime);

    // Validate Expected vs Actual
    const expectedSeverities = Array.isArray(testCase.expectedSeverity)
      ? testCase.expectedSeverity
      : [testCase.expectedSeverity];

    const expectedCategories = Array.isArray(testCase.expectedCategory)
      ? testCase.expectedCategory
      : [testCase.expectedCategory];

    const severityMatches = expectedSeverities.includes(actualVerdict.severity);
    const categoryMatches = expectedCategories.includes(actualVerdict.category);

    let status: TestExecutionStatus = 'FAIL';

    if (testCase.isRedirectSimulation) {
      // In redirect simulation, pass if redirect tracker detected suspicious hops AND destination is flagged
      if (actualRedirectChain?.hasSuspiciousHop && severityMatches) {
        status = 'PASS';
        notes.push('Redirect chain analysis successfully identified malicious destination hop');
      } else if (severityMatches) {
        status = 'WARNING';
        notes.push('Destination flagged, but intermediate hop warning was not triggered');
      } else {
        status = 'FAIL';
        notes.push('Failed to detect suspicious redirect destination');
      }
    } else if (severityMatches && categoryMatches) {
      status = 'PASS';
      notes.push(`Severity (${actualVerdict.severity}) and Category (${actualVerdict.category}) matched expectation`);
    } else if (severityMatches) {
      status = 'WARNING';
      notes.push(`Severity (${actualVerdict.severity}) matched, but category was ${actualVerdict.category} (expected ${expectedCategories.join('/')})`);
    } else {
      status = 'FAIL';
      notes.push(`Verdict mismatch: Got ${actualVerdict.severity}/${actualVerdict.category}, expected ${expectedSeverities.join('/')}/${expectedCategories.join('/')}`);
    }

    if (testCase.expectedSource && actualVerdict.source === testCase.expectedSource) {
      notes.push(`Detection source matched: ${actualVerdict.source}`);
    }

    return {
      testCase,
      status,
      actualVerdict,
      actualRedirectChain,
      durationMs,
      notes,
      executedAt: Date.now(),
    };
  }

  /**
   * Run all predefined test cases sequentially with progress notification
   */
  static async runAllTests(
    testCases: TestCase[],
    onProgress?: (completed: number, total: number, latestResult: TestResult) => void
  ): Promise<TestResult[]> {
    const results: TestResult[] = [];
    const total = testCases.length;

    for (let i = 0; i < total; i++) {
      const tc = testCases[i];
      const result = await this.runSingleTest(tc);
      results.push(result);
      if (onProgress) {
        onProgress(i + 1, total, result);
      }
    }

    return results;
  }
}
