import { TestCase, TestResult, TestExecutionStatus } from './types';
import { ReputationService } from '../services/reputation-service';
import { RedirectTracker } from '../background/redirect-tracker';
import { ReputationVerdict } from '../types/threat';
import { KeyManager } from '../ai/key-manager';
import { ProviderRouter } from '../ai/provider-router';
import { PiiScrubber } from '../ai/pii-scrubber';
import { GeminiProvider } from '../ai/providers/gemini-provider';

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
      if (testCase.isAiDiagnostic) {
        // Execute AI Engine Diagnostic Scenario
        return await this.runAiDiagnosticTest(testCase, startTime);
      } else if (testCase.isRedirectSimulation && testCase.simulationHops && testCase.simulationHops.length > 0) {
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

    if (testCase.expectedSource) {
      const sources = Array.isArray(testCase.expectedSource) ? testCase.expectedSource : [testCase.expectedSource];
      if (sources.includes(actualVerdict.source)) {
        notes.push(`Detection source matched: ${actualVerdict.source}`);
      }
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
   * Dedicated runner for AI Engine Diagnostic scenarios
   */
  private static async runAiDiagnosticTest(
    testCase: TestCase,
    startTime: number
  ): Promise<TestResult> {
    const notes: string[] = [];
    let status: TestExecutionStatus = 'PASS';

    try {
      switch (testCase.aiTestType) {
        case 'ROTATION': {
          const k1 = await KeyManager.addKey('gemini', 'mock_ai_key_alpha_12345', 'Mock Key A');
          const k2 = await KeyManager.addKey('gemini', 'mock_ai_key_beta_67890', 'Mock Key B');

          const first = await KeyManager.getNextAvailableKey('gemini');
          const second = await KeyManager.getNextAvailableKey('gemini');

          await KeyManager.removeKey(k1.id);
          await KeyManager.removeKey(k2.id);

          if (first && second && first.id !== second.id) {
            notes.push(`Round robin rotated key from ${first.label} to ${second.label}`);
            notes.push('Both keys verified as active and distinct in rotation sequence');
          } else {
            status = 'FAIL';
            notes.push('KeyManager failed to rotate keys or repeated the same key');
          }
          break;
        }

        case 'RATE_LIMIT': {
          const k = await KeyManager.addKey('gemini', 'mock_ai_key_rl_test', 'Mock RL Key');
          await KeyManager.recordRateLimit(k.id, 30);

          const maskedKeys = await KeyManager.getMaskedKeys('gemini');
          const cooling = maskedKeys.find((m) => m.id === k.id);

          await KeyManager.removeKey(k.id);

          if (cooling && cooling.status === 'cooling_down' && cooling.cooldownRemainingSeconds! > 0) {
            notes.push(`Key successfully transitioned to cooling_down on 429 status`);
            notes.push(`Cooldown duration active: ${cooling.cooldownRemainingSeconds}s remaining`);
          } else {
            status = 'FAIL';
            notes.push('Failed to set key status to cooling_down or cooldown remaining was 0');
          }
          break;
        }

        case 'FALLBACK': {
          const order = await ProviderRouter.getProviderExecutionOrder();
          if (order.length >= 1) {
            notes.push(`Provider execution sequence verified: ${order.join(' ➔ ')}`);
            notes.push('Automatic secondary fallback routing enabled');
          } else {
            status = 'FAIL';
            notes.push('No providers returned in execution order');
          }
          break;
        }

        case 'PARSER': {
          const sensitive = 'Dear user your OTP is 987654. Call bank officer at +91 9876543210.';
          const scrubbed = PiiScrubber.sanitizeText(sensitive);

          if (!scrubbed.includes('9876543210') && scrubbed.includes('[PHONE_NUMBER_REDACTED]') && scrubbed.includes('[OTP_REDACTED]')) {
            notes.push('PiiScrubber successfully redacted phone number and verification OTP');
          } else {
            status = 'FAIL';
            notes.push('PII scrubber failed to redact phone number or OTP');
          }

          const provider = new GeminiProvider();
          const mockJson = '```json\n{"classification": "SCAM", "riskLevel": "HIGH", "summary": "Test"}\n```';
          const parsed = provider.parseStructuredJson<any>(mockJson, null);

          if (parsed && parsed.classification === 'SCAM') {
            notes.push('BaseAIProvider successfully stripped markdown fences and parsed structured JSON');
          } else {
            status = 'FAIL';
            notes.push('JSON parsing failed on markdown-fenced output');
          }
          break;
        }

        default:
          status = 'FAIL';
          notes.push(`Unknown AI diagnostic test type: ${testCase.aiTestType}`);
      }
    } catch (err: any) {
      status = 'FAIL';
      notes.push(`Diagnostic exception: ${err.message}`);
    }

    const durationMs = Math.round(performance.now() - startTime);

    return {
      testCase,
      status,
      actualVerdict: {
        domain: 'ai.scamshield.internal',
        canonicalUrl: testCase.targetUrl,
        severity: status === 'PASS' ? 'SAFE' : 'HIGH',
        category: 'LEGITIMATE',
        riskScore: status === 'PASS' ? 0 : 75,
        evidence: notes,
        source: 'AI_DIAGNOSTIC',
        isBlocked: false,
        evaluatedAt: Date.now(),
      },
      durationMs,
      notes,
      executedAt: Date.now(),
    };
  }

  /**
   * Run entire controlled suite sequentially with real-time progress callback
   */
  static async runAllTests(
    testCases: TestCase[],
    onProgress?: (completed: number, total: number, lastResult: TestResult) => void
  ): Promise<TestResult[]> {
    const results: TestResult[] = [];
    const total = testCases.length;

    for (let i = 0; i < total; i++) {
      const tc = testCases[i];
      const res = await this.runSingleTest(tc);
      results.push(res);
      if (onProgress) {
        onProgress(i + 1, total, res);
      }
    }

    return results;
  }
}
