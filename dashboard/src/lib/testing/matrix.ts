/**
 * ScamShield Automated Testing Matrix & Adversarial Engine
 *
 * Implements 18 real adversarial attack transformations,
 * multi-language/multi-category test cases, and execution engine.
 */

import { ScamShieldScanner, AnalysisResult } from '../analysis/scanner';
import { getDatabase } from '../db';
import { randomUUID } from 'crypto';

export type AttackType =
  | 'NONE'
  | 'SPACING_INJECTION'
  | 'HOMOGLYPH_CYRILLIC'
  | 'CHAR_ELONGATION'
  | 'DELIMITER_INSERTION'
  | 'LEETSPEAK'
  | 'URL_SUBDOMAIN_STUFFING'
  | 'URL_HEX_IP'
  | 'ZERO_WIDTH_CHARS'
  | 'CASE_TOGGLE'
  | 'TYPO_INJECTION'
  | 'PUNCTUATION_STRIP'
  | 'MIXED_LANGUAGE_HINGLISH'
  | 'PLEASANTRY_CAMOUFLAGE'
  | 'EMOJI_DISTRACTION'
  | 'MESSAGE_FRAGMENTATION'
  | 'DISGUISED_UPI'
  | 'PHONE_OBFUSCATION'
  | 'LEGAL_DISCLAIMER_CAMOUFLAGE';

export interface TestCaseInput {
  id: string;
  content: string;
  contentType: 'TEXT' | 'URL' | 'DOCUMENT' | 'IMAGE' | 'PHONE' | 'UPI';
  language: string;
  category: string;
  expectedLabel: 'SCAM' | 'LEGITIMATE';
  attackType?: AttackType;
}

export interface TestCaseResult {
  sampleId: string;
  content: string;
  contentType: string;
  language: string;
  category: string;
  attackType: AttackType;
  expectedLabel: 'SCAM' | 'LEGITIMATE';
  predictedLabel: 'SCAM' | 'LEGITIMATE';
  scamProbability: number;
  passed: boolean;
  latencyMs: number;
  explanation: string;
}

export interface TestMatrixSummary {
  runId: string;
  modelName: string;
  datasetVersion: string;
  testProfile: string;
  sampleCount: number;
  status: 'PASSED' | 'FAILED';
  accuracy: number;
  precision: number;
  recall: number;
  f1Score: number;
  fpr: number;
  avgLatencyMs: number;
  resultsByCategory: Record<string, { total: number; passed: number; accuracy: number }>;
  resultsByLanguage: Record<string, { total: number; passed: number; accuracy: number }>;
  resultsByAttack: Record<string, { total: number; passed: number; accuracy: number }>;
  details: TestCaseResult[];
}

export class AdversarialTransformer {
  /**
   * 18 Adversarial Attack Transformations
   */
  static apply(text: string, attack: AttackType): string {
    switch (attack) {
      case 'SPACING_INJECTION':
        // Insert spaces inside scam keywords (e.g. U R G E N T, K Y C)
        return text.replace(/\b(urgent|kyc|sbi|block|verify|account|bank)\b/gi, (match) =>
          match.split('').join(' ')
        );

      case 'HOMOGLYPH_CYRILLIC':
        // Replace Latin characters with Cyrillic lookalikes: a->а (U+0430), o->о (U+043E), e->е (U+0435), p->р (U+0440)
        return text
          .replace(/a/g, '\u0430')
          .replace(/o/g, '\u043E')
          .replace(/e/g, '\u0435')
          .replace(/p/g, '\u0440');

      case 'CHAR_ELONGATION':
        // Duplicate vowels/consonants
        return text.replace(/([aeiou])/gi, '$1$1$1');

      case 'DELIMITER_INSERTION':
        // Insert dots or underscores between letters
        return text.replace(/\b([A-Za-z]{3,7})\b/g, (w) => w.split('').join('.'));

      case 'LEETSPEAK':
        // Replace letters with numbers
        return text
          .replace(/e/gi, '3')
          .replace(/i/gi, '1')
          .replace(/o/gi, '0')
          .replace(/a/gi, '@')
          .replace(/s/gi, '$');

      case 'URL_SUBDOMAIN_STUFFING':
        return text.replace(
          /(https?:\/\/[^\s]+)/gi,
          'https://sbi.bank.account-security-alert.xyz/portal/verify-now'
        );

      case 'URL_HEX_IP':
        return text.replace(
          /(https?:\/\/[^\s]+)/gi,
          'http://0xd8.0x3a.0xd6.0xe1/update.php'
        );

      case 'ZERO_WIDTH_CHARS':
        // Insert zero-width spaces (\u200B)
        return text.split('').join('\u200B');

      case 'CASE_TOGGLE':
        // Random upper/lower case
        return text
          .split('')
          .map((c, i) => (i % 2 === 0 ? c.toUpperCase() : c.toLowerCase()))
          .join('');

      case 'TYPO_INJECTION':
        // Transpose adjacent characters in key words
        return text
          .replace(/urgent/gi, 'urgnet')
          .replace(/verify/gi, 'verfiy')
          .replace(/account/gi, 'acount')
          .replace(/immediately/gi, 'immedaitely');

      case 'PUNCTUATION_STRIP':
        return text.replace(/[.,\/#!$%\^&\*;:{}=\-_`~()]/g, '');

      case 'MIXED_LANGUAGE_HINGLISH':
        return `${text} Aapka account turant band kar diya jayega kripya verify karein bina deri ke.`;

      case 'PLEASANTRY_CAMOUFLAGE':
        return `Respected customer, we hope you are having a wonderful day with your family. Regarding your safe banking relationship: ${text} Thank you for your continued loyalty and trust.`;

      case 'EMOJI_DISTRACTION':
        return `🚨🚨 IMPORTANT NOTIFICATION ⚠️⚠️ ${text} ‼️ CLICK FAST 💸💰🏦`;

      case 'MESSAGE_FRAGMENTATION':
        return text.substring(0, Math.floor(text.length * 0.55)) + '... (Click link to continue)';

      case 'DISGUISED_UPI':
        return `${text} Send confirmation payment to refund-nodal-officer@ybl or support-desk@oksbi`;

      case 'PHONE_OBFUSCATION':
        return text.replace(/(\d{5})(\d{5})/g, '$1 - $2');

      case 'LEGAL_DISCLAIMER_CAMOUFLAGE':
        return `${text}\n\n[CONFIDENTIAL: Under Section 43A of the IT Act 2000, this alert is officially dispatched by Cyber Security Task Force. Strictly comply to avoid legal penalties.]`;

      default:
        return text;
    }
  }
}

/**
 * Standard Multi-Domain Multi-Language Seed Test Suite
 */
export const BASE_TEST_SUITE: TestCaseInput[] = [
  // 1. Banking KYC (English)
  {
    id: 'tc-001',
    content: 'URGENT: Dear Customer, your SBI bank account will be blocked today due to incomplete KYC. Update immediately to avoid suspension: https://sbi-kyc-alert.example/verify',
    contentType: 'TEXT',
    language: 'en',
    category: 'BANKING_KYC',
    expectedLabel: 'SCAM',
  },
  // 2. Electricity Disconnection (English)
  {
    id: 'tc-002',
    content: 'Dear consumer your electricity power will be disconnected tonight at 9:30 pm from electricity office because your previous month bill was not updated. Please immediately call 9876543210.',
    contentType: 'TEXT',
    language: 'en',
    category: 'ELECTRICITY',
    expectedLabel: 'SCAM',
  },
  // 3. Digital Arrest (English)
  {
    id: 'tc-003',
    content: 'CRIMINAL NOTICE: CBI & Mumbai Police Cyber Crime Cell have seized a contraband parcel sent via FedEx in your name containing narcotics and fake passports. A digital arrest warrant is issued. Connect on Skype immediately.',
    contentType: 'TEXT',
    language: 'en',
    category: 'DIGITAL_ARREST',
    expectedLabel: 'SCAM',
  },
  // 4. Job Offer Task Scam (English)
  {
    id: 'tc-004',
    content: 'Congratulations! Part-time work from home opportunity. Like 3 YouTube videos daily and earn Rs.3000 to Rs.8000 daily payout to UPI. Contact manager on Telegram: @hr_work_online',
    contentType: 'TEXT',
    language: 'en',
    category: 'JOB_OFFER',
    expectedLabel: 'SCAM',
  },
  // 5. UPI PIN Refund Scam (English)
  {
    id: 'tc-005',
    content: 'Dear user, Rs. 5,000 cash reward cashback is credited to your GooglePay. Click collect link and enter your 6-digit UPI PIN to claim instant refund.',
    contentType: 'TEXT',
    language: 'en',
    category: 'UPI_FRAUD',
    expectedLabel: 'SCAM',
  },
  // 6. Legitimate Bank OTP (English) - False Positive test
  {
    id: 'tc-006',
    content: '648291 is your OTP for purchase of Rs 1,450.00 at AMAZON INDIA with SBI Debit Card ending 4012. Do not share OTP with anyone including bank staff.',
    contentType: 'TEXT',
    language: 'en',
    category: 'LEGITIMATE_TRANSACTION',
    expectedLabel: 'LEGITIMATE',
  },
  // 7. Legitimate Utility Receipt (English)
  {
    id: 'tc-007',
    content: 'Thank you for your payment of Rs 1,840 against Electricity Consumer No 10294819. Transaction ID: TXN94810283. Your next meter reading will be on 15th next month.',
    contentType: 'TEXT',
    language: 'en',
    category: 'LEGITIMATE_TRANSACTION',
    expectedLabel: 'LEGITIMATE',
  },
  // 8. Banking KYC (Hindi)
  {
    id: 'tc-008',
    content: 'Priya grahak, aapka PNB khata aaj aadhar KYC update na hone par band kar diya jayega. Turant link par click karke verify karein: http://pnb-online-update.top',
    contentType: 'TEXT',
    language: 'hi',
    category: 'BANKING_KYC',
    expectedLabel: 'SCAM',
  },
  // 9. Electricity (Hindi/Hinglish)
  {
    id: 'tc-009',
    content: 'Aapka bijli connection aaj raat 10 baje kat diya jayega kyunki pichla bill jama nahi hai. Turant bijli adhikari se sampark karein: 9123456789',
    contentType: 'TEXT',
    language: 'hi',
    category: 'ELECTRICITY',
    expectedLabel: 'SCAM',
  },
  // 10. Legitimate Personal Chat (Hindi/Hinglish)
  {
    id: 'tc-010',
    content: 'Bhai kal meeting ke baad dinner ke liye chalte hain, maine restaurant book kar diya hai 8 baje.',
    contentType: 'TEXT',
    language: 'hi',
    category: 'LEGITIMATE_CONVERSATION',
    expectedLabel: 'LEGITIMATE',
  },
  // 11. Malicious Phishing URL
  {
    id: 'tc-011',
    content: 'http://sbi-card-reward-points-claim.top/login',
    contentType: 'URL',
    language: 'en',
    category: 'PHISHING_URL',
    expectedLabel: 'SCAM',
  },
  // 12. Legitimate Government Portal URL
  {
    id: 'tc-012',
    content: 'https://incometax.gov.in/iec/foportal',
    contentType: 'URL',
    language: 'en',
    category: 'LEGITIMATE_URL',
    expectedLabel: 'LEGITIMATE',
  },
];

export class TestingMatrixEngine {
  /**
   * Generates a concrete test suite based on the profile
   */
  static generateTestSuite(profile: string): TestCaseInput[] {
    const list: TestCaseInput[] = [];

    switch (profile.toUpperCase()) {
      case 'QUICK':
        // Run baseline 12 test cases without attacks
        return BASE_TEST_SUITE.map((tc) => ({ ...tc, attackType: 'NONE' }));

      case 'ADVERSARIAL': {
        // Run all scam test cases against all 18 adversarial attacks
        const attacks: AttackType[] = [
          'SPACING_INJECTION',
          'HOMOGLYPH_CYRILLIC',
          'CHAR_ELONGATION',
          'DELIMITER_INSERTION',
          'LEETSPEAK',
          'URL_SUBDOMAIN_STUFFING',
          'URL_HEX_IP',
          'ZERO_WIDTH_CHARS',
          'CASE_TOGGLE',
          'TYPO_INJECTION',
          'PUNCTUATION_STRIP',
          'MIXED_LANGUAGE_HINGLISH',
          'PLEASANTRY_CAMOUFLAGE',
          'EMOJI_DISTRACTION',
          'MESSAGE_FRAGMENTATION',
          'DISGUISED_UPI',
          'PHONE_OBFUSCATION',
          'LEGAL_DISCLAIMER_CAMOUFLAGE',
        ];

        let idCounter = 1;
        for (const base of BASE_TEST_SUITE.filter((t) => t.expectedLabel === 'SCAM')) {
          for (const atk of attacks) {
            const transformed = AdversarialTransformer.apply(base.content, atk);
            list.push({
              id: `adv-${idCounter++}`,
              content: transformed,
              contentType: base.contentType,
              language: base.language,
              category: base.category,
              expectedLabel: 'SCAM',
              attackType: atk,
            });
          }
        }
        // Add legitimate controls to measure false positive impact
        for (const base of BASE_TEST_SUITE.filter((t) => t.expectedLabel === 'LEGITIMATE')) {
          list.push({ ...base, id: `adv-ctrl-${idCounter++}`, attackType: 'NONE' });
        }
        return list;
      }

      case 'LANGUAGE': {
        // Test cross-lingual variants
        const languages = ['en', 'hi', 'ta', 'te', 'mr', 'bn'];
        let idCounter = 1;
        for (const base of BASE_TEST_SUITE) {
          list.push({ ...base, id: `lang-${idCounter++}`, attackType: 'NONE' });
        }
        return list;
      }

      case 'DOCUMENT': {
        // Safe document parsing test cases
        return [
          {
            id: 'doc-001',
            content: 'URGENT NOTICE: Legal action initiated for non-payment of electricity bill. Settle immediately.',
            contentType: 'DOCUMENT',
            language: 'en',
            category: 'ELECTRICITY',
            expectedLabel: 'SCAM',
            attackType: 'NONE',
          },
          {
            id: 'doc-002',
            content: 'Project Invoice 2026 for web development services. Payment terms: 30 days via NEFT.',
            contentType: 'DOCUMENT',
            language: 'en',
            category: 'LEGITIMATE_TRANSACTION',
            expectedLabel: 'LEGITIMATE',
            attackType: 'NONE',
          },
        ];
      }

      case 'STANDARD':
      case 'FULL':
      default: {
        // Standard profile: Base + selected representative attacks
        let idCounter = 1;
        for (const base of BASE_TEST_SUITE) {
          list.push({ ...base, id: `std-${idCounter++}`, attackType: 'NONE' });
          if (base.expectedLabel === 'SCAM') {
            for (const atk of [
              'SPACING_INJECTION',
              'HOMOGLYPH_CYRILLIC',
              'LEETSPEAK',
              'URL_SUBDOMAIN_STUFFING',
              'MIXED_LANGUAGE_HINGLISH',
              'EMOJI_DISTRACTION',
            ] as AttackType[]) {
              list.push({
                id: `std-${idCounter++}`,
                content: AdversarialTransformer.apply(base.content, atk),
                contentType: base.contentType,
                language: base.language,
                category: base.category,
                expectedLabel: 'SCAM',
                attackType: atk,
              });
            }
          }
        }
        return list;
      }
    }
  }

  /**
   * Executes the test matrix and persists results in SQLite
   */
  static async runMatrix(
    profile = 'STANDARD',
    modelName = 'ScamShield-Ensemble-v3',
    userId?: string
  ): Promise<TestMatrixSummary> {
    const runId = `RUN-${Date.now().toString(36).toUpperCase()}-${Math.floor(Math.random() * 1000)}`;
    const testCases = this.generateTestSuite(profile);
    const db = getDatabase();

    // 1. Initialize Test Run record
    const testRunDbId = randomUUID();
    db.prepare(`
      INSERT INTO test_runs (
        id, run_id, user_id, model_name, dataset_version, test_profile, sample_count, status, created_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, 'RUNNING', datetime('now'))
    `).run(
      testRunDbId,
      runId,
      userId || null,
      modelName,
      'v3.0.0-dataset',
      profile,
      testCases.length
    );

    const results: TestCaseResult[] = [];
    let truePositives = 0;
    let falsePositives = 0;
    let trueNegatives = 0;
    let falseNegatives = 0;
    let totalLatency = 0;

    const byCategory: Record<string, { total: number; passed: number; accuracy: number }> = {};
    const byLanguage: Record<string, { total: number; passed: number; accuracy: number }> = {};
    const byAttack: Record<string, { total: number; passed: number; accuracy: number }> = {};

    // 2. Execute Each Test Case
    for (const tc of testCases) {
      const start = Date.now();
      let scanResult: AnalysisResult;

      if (tc.contentType === 'URL') {
        scanResult = await ScamShieldScanner.scanUrl(tc.content);
      } else {
        scanResult = await ScamShieldScanner.scanText(tc.content, tc.contentType, tc.language);
      }
      const latencyMs = Math.max(1, Date.now() - start);
      totalLatency += latencyMs;

      // Verdict logic: SCAM if riskScore >= 50 or classification is SUSPICIOUS/HIGH/CRITICAL
      const predictedLabel: 'SCAM' | 'LEGITIMATE' =
        scanResult.riskScore >= 50 || scanResult.riskClassification !== 'SAFE'
          ? 'SCAM'
          : 'LEGITIMATE';

      const passed = predictedLabel === tc.expectedLabel;

      if (tc.expectedLabel === 'SCAM') {
        if (predictedLabel === 'SCAM') truePositives++;
        else falseNegatives++;
      } else {
        if (predictedLabel === 'LEGITIMATE') trueNegatives++;
        else falsePositives++;
      }

      const atk = tc.attackType || 'NONE';
      const res: TestCaseResult = {
        sampleId: tc.id,
        content: tc.content,
        contentType: tc.contentType,
        language: tc.language,
        category: tc.category,
        attackType: atk,
        expectedLabel: tc.expectedLabel,
        predictedLabel,
        scamProbability: scanResult.confidence,
        passed,
        latencyMs,
        explanation: scanResult.explanation,
      };
      results.push(res);

      // Record in Category breakdown
      if (!byCategory[tc.category]) byCategory[tc.category] = { total: 0, passed: 0, accuracy: 0 };
      byCategory[tc.category].total++;
      if (passed) byCategory[tc.category].passed++;

      // Record in Language breakdown
      if (!byLanguage[tc.language]) byLanguage[tc.language] = { total: 0, passed: 0, accuracy: 0 };
      byLanguage[tc.language].total++;
      if (passed) byLanguage[tc.language].passed++;

      // Record in Attack breakdown
      if (!byAttack[atk]) byAttack[atk] = { total: 0, passed: 0, accuracy: 0 };
      byAttack[atk].total++;
      if (passed) byAttack[atk].passed++;

      // Persist individual test case in DB
      db.prepare(`
        INSERT INTO test_cases (
          id, test_run_id, sample_id, content, content_type, language, category,
          attack_type, expected_label, predicted_label, scam_probability, passed, latency_ms
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `).run(
        randomUUID(),
        testRunDbId,
        tc.id,
        tc.content,
        tc.contentType,
        tc.language,
        tc.category,
        atk,
        tc.expectedLabel,
        predictedLabel,
        scanResult.confidence,
        passed ? 1 : 0,
        latencyMs
      );
    }

    // Calculate accuracy for breakdowns
    for (const k of Object.keys(byCategory)) {
      byCategory[k].accuracy = Math.round((byCategory[k].passed / byCategory[k].total) * 1000) / 10;
    }
    for (const k of Object.keys(byLanguage)) {
      byLanguage[k].accuracy = Math.round((byLanguage[k].passed / byLanguage[k].total) * 1000) / 10;
    }
    for (const k of Object.keys(byAttack)) {
      byAttack[k].accuracy = Math.round((byAttack[k].passed / byAttack[k].total) * 1000) / 10;
    }

    // 3. Compute Aggregate Metrics
    const totalSamples = testCases.length;
    const accuracy = totalSamples > 0 ? (truePositives + trueNegatives) / totalSamples : 0;
    const precision =
      truePositives + falsePositives > 0
        ? truePositives / (truePositives + falsePositives)
        : 1.0;
    const recall =
      truePositives + falseNegatives > 0
        ? truePositives / (truePositives + falseNegatives)
        : 1.0;
    const f1Score =
      precision + recall > 0 ? (2 * precision * recall) / (precision + recall) : 0;
    const fpr =
      falsePositives + trueNegatives > 0
        ? falsePositives / (falsePositives + trueNegatives)
        : 0;
    const avgLatencyMs = Math.round((totalLatency / Math.max(1, totalSamples)) * 10) / 10;

    const status = accuracy >= 0.85 ? 'PASSED' : 'FAILED';

    const metricsJson = JSON.stringify({
      truePositives,
      falsePositives,
      trueNegatives,
      falseNegatives,
      byCategory,
      byLanguage,
      byAttack,
      avgLatencyMs,
    });

    // 4. Update Test Run Record in SQLite
    db.prepare(`
      UPDATE test_runs
      SET status = ?, accuracy = ?, precision = ?, recall = ?, f1_score = ?, fpr = ?, metrics_json = ?
      WHERE id = ?
    `).run(
      status,
      Math.round(accuracy * 1000) / 10,
      Math.round(precision * 1000) / 10,
      Math.round(recall * 1000) / 10,
      Math.round(f1Score * 1000) / 10,
      Math.round(fpr * 1000) / 10,
      metricsJson,
      testRunDbId
    );

    return {
      runId,
      modelName,
      datasetVersion: 'v3.0.0-dataset',
      testProfile: profile,
      sampleCount: totalSamples,
      status,
      accuracy: Math.round(accuracy * 1000) / 10,
      precision: Math.round(precision * 1000) / 10,
      recall: Math.round(recall * 1000) / 10,
      f1Score: Math.round(f1Score * 1000) / 10,
      fpr: Math.round(fpr * 1000) / 10,
      avgLatencyMs,
      resultsByCategory: byCategory,
      resultsByLanguage: byLanguage,
      resultsByAttack: byAttack,
      details: results,
    };
  }
}
