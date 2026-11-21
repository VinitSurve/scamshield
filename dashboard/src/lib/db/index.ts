/**
 * ScamShield Community Platform Database Client & Repository
 *
 * Uses Node.js native DatabaseSync for zero-dependency, ACID-compliant persistence.
 */

import { DatabaseSync } from 'node:sqlite';
import path from 'path';
import fs from 'fs';
import { CREATE_TABLES_SQL } from './schema';

let dbInstance: DatabaseSync | null = null;

export function getDb(): DatabaseSync {
  if (!dbInstance) {
    const dataDir = path.resolve(process.cwd(), 'data');
    if (!fs.existsSync(dataDir)) {
      fs.mkdirSync(dataDir, { recursive: true });
    }
    const dbPath = path.join(dataDir, 'scamshield_community.db');
    dbInstance = new DatabaseSync(dbPath);

    // Enable WAL and foreign keys
    dbInstance.exec('PRAGMA foreign_keys = ON;');
    dbInstance.exec(CREATE_TABLES_SQL);
    seedInitialData(dbInstance);
  }
  return dbInstance;
}

export const getDatabase = getDb;

function seedInitialData(db: DatabaseSync): void {
  // Check if admin user exists
  const checkUser = db.prepare('SELECT count(*) as count FROM users').get() as { count: number };
  if (checkUser && checkUser.count > 0) {
    return; // Already seeded
  }

  const now = new Date().toISOString();

  // Create default admin and demo user (password is "ScamShield@2026" hashed)
  // scrypt hash placeholder for demo initialization
  const defaultHash = '8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918'; // sha256 placeholder or scrypt

  const insertUser = db.prepare(`
    INSERT INTO users (id, username, email, password_hash, role, trust_score, created_at)
    VALUES (?, ?, ?, ?, ?, ?, ?)
  `);

  insertUser.run('usr_admin_01', 'scamshield_admin', 'admin@scamshield.org', defaultHash, 'admin', 100, now);
  insertUser.run('usr_mod_01', 'cyber_moderator', 'mod@scamshield.org', defaultHash, 'moderator', 80, now);
  insertUser.run('usr_citizen_01', 'rajesh_mumbai', 'rajesh@example.com', defaultHash, 'user', 25, now);
  insertUser.run('usr_citizen_02', 'priya_pune', 'priya@example.com', defaultHash, 'user', 20, now);

  // Insert initial realistic community scam reports across verified Indian typologies
  const insertPost = db.prepare(`
    INSERT INTO community_posts (
      id, user_id, title, description, category, scam_type, language, platform, severity,
      content, extracted_indicators, verification_status, upvotes, downvotes, view_count, tags, is_redacted, created_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `);

  const initialPosts = [
    {
      id: 'post_kyc_01',
      userId: 'usr_citizen_01',
      title: 'Urgent SBI KYC suspension SMS with suspicious is.gd link',
      description: 'Received SMS threatening bank account block within 24 hours. The shortened URL leads to a fake SBI Yono login phishing portal.',
      category: 'BANKING_KYC',
      scamType: 'SMS Phishing (Smishing)',
      language: 'en',
      platform: 'SMS',
      severity: 'CRITICAL',
      content: 'Dear Customer your Icici bank Accounts KYC has been suspended please update your KYC click in link and activate your icici bank Accounts https://is.gd/J9gaHq.iciciBank.KYC',
      indicators: JSON.stringify([
        { type: 'URL', value: 'https://is.gd/J9gaHq.iciciBank.KYC', risk: 'HIGH', note: 'Shortened phishing portal' },
        { type: 'BRAND', value: 'ICICI Bank', risk: 'HIGH', note: 'Brand impersonation' }
      ]),
      status: 'VERIFIED',
      upvotes: 42,
      downvotes: 1,
      views: 310,
      tags: JSON.stringify(['sbi', 'icici', 'kyc', 'phishing', 'sms']),
    },
    {
      id: 'post_elec_02',
      userId: 'usr_citizen_02',
      title: 'Mahavitaran electricity power cutoff threat on WhatsApp tonight',
      description: 'Threatens power disconnection at 09:30 PM due to unpaid surcharge and gives a personal mobile number to call.',
      category: 'ELECTRICITY',
      scamType: 'Utility Extortion',
      language: 'mr',
      platform: 'WhatsApp',
      severity: 'HIGH',
      content: 'प्रिय उपभोक्ता, महावितरण कडून तुमची वीज आज रात्री 9:30 वाजता खंडित करण्यात येईल कारण तुमचे मागील बिल अपडेट झाले नाही. वीज पुरवठा चालू ठेवण्यासाठी त्वरित आमच्या वीज अधिकारी 9876543210 वर कॉल करा.',
      indicators: JSON.stringify([
        { type: 'PHONE', value: '+91 9876543210', risk: 'HIGH', note: 'Private mobile number, not official desk' },
        { type: 'UTILITY', value: 'Mahavitaran / MSEDCL', risk: 'HIGH', note: 'State utility impersonation' }
      ]),
      status: 'VERIFIED',
      upvotes: 38,
      downvotes: 0,
      views: 245,
      tags: JSON.stringify(['electricity', 'msedcl', 'mahavitaran', 'extortion']),
    },
    {
      id: 'post_cbi_03',
      userId: 'usr_citizen_01',
      title: 'Fake CBI Digital Arrest notice threatening Skype interrogation',
      description: 'Caller claimed my Aadhaar was found in a narcotics parcel at Mumbai airport and demanded joining Skype video call.',
      category: 'DIGITAL_ARREST',
      scamType: 'Law Enforcement Extortion',
      language: 'en',
      platform: 'WhatsApp',
      severity: 'CRITICAL',
      content: 'CBI LEGAL NOTICE: A parcel sent under your Aadhaar containing MDMA has been intercepted. You are placed under Digital Arrest. Immediately join Skype video interrogation room or face non-bailable arrest warrant.',
      indicators: JSON.stringify([
        { type: 'AUTHORITY', value: 'Central Bureau of Investigation (CBI)', risk: 'CRITICAL', note: 'Digital arrest impersonation' },
        { type: 'TACTIC', value: 'Psychological coercion / Video call demand', risk: 'CRITICAL', note: 'Illegal extortion' }
      ]),
      status: 'VERIFIED',
      upvotes: 56,
      downvotes: 2,
      views: 480,
      tags: JSON.stringify(['digital-arrest', 'cbi', 'police', 'extortion', 'narcotics']),
    },
    {
      id: 'post_upi_04',
      userId: 'usr_citizen_02',
      title: 'Fraudulent Swiggy refund collect request on PhonePe / Google Pay',
      description: 'Fraudster sent a ₹1,500 collect request claiming it was a refund and told me to enter my UPI PIN to receive money.',
      category: 'UPI_FRAUD',
      scamType: 'UPI Collect Fraud',
      language: 'hinglish',
      platform: 'UPI / PhonePe',
      severity: 'HIGH',
      content: 'Swiggy order cancel refund approved: Pay request of Rs 1,500 from swiggy.refund@okaxis. Enter UPI PIN to receive payment in your account.',
      indicators: JSON.stringify([
        { type: 'UPI_ID', value: 'swiggy.refund@okaxis', risk: 'HIGH', note: 'Fraudulent collect handle' },
        { type: 'TACTIC', value: 'Reverse PIN deception (PIN deducts money)', risk: 'HIGH', note: 'PIN collect trap' }
      ]),
      status: 'COMMUNITY_SUPPORTED',
      upvotes: 29,
      downvotes: 1,
      views: 190,
      tags: JSON.stringify(['upi', 'swiggy', 'refund', 'collect', 'phonepe']),
    },
    {
      id: 'post_job_05',
      userId: 'usr_citizen_01',
      title: 'Telegram YouTube like and rating task scam paying ₹3000/day',
      description: 'Invites you to like videos for ₹50 each, pays small amounts initially, then demands ₹10,000 prepaid merchant deposit.',
      category: 'JOB_OFFER',
      scamType: 'Prepaid Task Fraud',
      language: 'en',
      platform: 'Telegram',
      severity: 'HIGH',
      content: 'Part time online job offer: Earn Rs. 2,500 to Rs. 8,000 daily from mobile just by liking YouTube videos. Contact HR Priya on Telegram @DailyEarnings2026.',
      indicators: JSON.stringify([
        { type: 'TELEGRAM', value: '@DailyEarnings2026', risk: 'HIGH', note: 'Fraudulent task dispatcher' },
        { type: 'TACTIC', value: 'Advance fee prepaid task trapping', risk: 'HIGH', note: 'Task scam' }
      ]),
      status: 'COMMUNITY_SUPPORTED',
      upvotes: 31,
      downvotes: 0,
      views: 215,
      tags: JSON.stringify(['job', 'telegram', 'youtube', 'task', 'advance-fee']),
    }
  ];

  for (const p of initialPosts) {
    insertPost.run(
      p.id, p.userId, p.title, p.description, p.category, p.scamType, p.language,
      p.platform, p.severity, p.content, p.indicators, p.status, p.upvotes, p.downvotes,
      p.views, p.tags, 0, now
    );
  }
}
