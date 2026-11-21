/**
 * ScamShield Community Platform Database Schema
 *
 * Implements relational schema with foreign keys, constraints, and indexes.
 */

export const CREATE_TABLES_SQL = `
CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY,
  username TEXT UNIQUE NOT NULL,
  email TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'user', -- 'user', 'moderator', 'admin'
  trust_score INTEGER NOT NULL DEFAULT 10,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS sessions (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  token TEXT UNIQUE NOT NULL,
  expires_at TEXT NOT NULL,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS community_posts (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  title TEXT NOT NULL,
  description TEXT NOT NULL,
  category TEXT NOT NULL,
  scam_type TEXT NOT NULL,
  language TEXT NOT NULL DEFAULT 'en',
  platform TEXT NOT NULL DEFAULT 'SMS',
  severity TEXT NOT NULL DEFAULT 'HIGH', -- 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'
  content TEXT NOT NULL,
  extracted_indicators TEXT NOT NULL DEFAULT '[]', -- JSON string
  verification_status TEXT NOT NULL DEFAULT 'UNVERIFIED', -- 'UNVERIFIED', 'COMMUNITY_SUPPORTED', 'UNDER_REVIEW', 'VERIFIED', 'FALSE_REPORT', 'RESOLVED'
  upvotes INTEGER NOT NULL DEFAULT 0,
  downvotes INTEGER NOT NULL DEFAULT 0,
  view_count INTEGER NOT NULL DEFAULT 0,
  tags TEXT NOT NULL DEFAULT '[]', -- JSON string
  is_redacted INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS post_votes (
  id TEXT PRIMARY KEY,
  post_id TEXT NOT NULL REFERENCES community_posts(id) ON DELETE CASCADE,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  vote_type TEXT NOT NULL, -- 'UP', 'DOWN'
  created_at TEXT NOT NULL,
  UNIQUE(post_id, user_id)
);

CREATE TABLE IF NOT EXISTS comments (
  id TEXT PRIMARY KEY,
  post_id TEXT NOT NULL REFERENCES community_posts(id) ON DELETE CASCADE,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  parent_id TEXT REFERENCES comments(id) ON DELETE CASCADE,
  content TEXT NOT NULL,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS bookmarks (
  id TEXT PRIMARY KEY,
  post_id TEXT NOT NULL REFERENCES community_posts(id) ON DELETE CASCADE,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  created_at TEXT NOT NULL,
  UNIQUE(post_id, user_id)
);

CREATE TABLE IF NOT EXISTS reports (
  id TEXT PRIMARY KEY,
  target_type TEXT NOT NULL, -- 'post', 'comment', 'user'
  target_id TEXT NOT NULL,
  reporter_user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  reason TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'PENDING', -- 'PENDING', 'REVIEWED', 'DISMISSED'
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS moderation_actions (
  id TEXT PRIMARY KEY,
  moderator_user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  target_type TEXT NOT NULL,
  target_id TEXT NOT NULL,
  action_type TEXT NOT NULL, -- 'VERIFY', 'FLAG_FALSE_REPORT', 'REDACT', 'RESOLVE', 'DELETE'
  notes TEXT,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS test_runs (
  id TEXT PRIMARY KEY,
  run_id TEXT UNIQUE NOT NULL,
  user_id TEXT REFERENCES users(id) ON DELETE SET NULL,
  model_name TEXT NOT NULL,
  dataset_version TEXT NOT NULL,
  test_profile TEXT NOT NULL,
  sample_count INTEGER NOT NULL,
  status TEXT NOT NULL DEFAULT 'QUEUED', -- 'QUEUED', 'RUNNING', 'PASSED', 'FAILED'
  accuracy REAL,
  precision REAL,
  recall REAL,
  f1_score REAL,
  fpr REAL,
  metrics_json TEXT NOT NULL DEFAULT '{}',
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS test_cases (
  id TEXT PRIMARY KEY,
  test_run_id TEXT NOT NULL REFERENCES test_runs(id) ON DELETE CASCADE,
  sample_id TEXT NOT NULL,
  content TEXT NOT NULL,
  content_type TEXT NOT NULL,
  language TEXT NOT NULL,
  category TEXT NOT NULL,
  attack_type TEXT,
  expected_label TEXT NOT NULL,
  predicted_label TEXT NOT NULL,
  scam_probability REAL NOT NULL,
  passed INTEGER NOT NULL,
  latency_ms REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS benchmark_contributions (
  id TEXT PRIMARY KEY,
  post_id TEXT REFERENCES community_posts(id) ON DELETE SET NULL,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  content TEXT NOT NULL,
  suggested_label TEXT NOT NULL,
  category TEXT NOT NULL,
  language TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'SUBMITTED', -- 'SUBMITTED', 'VALIDATION', 'PRIVACY_REVIEW', 'DUPLICATE_CHECK', 'LABEL_REVIEW', 'MODERATOR_APPROVAL', 'BENCHMARK_ELIGIBLE', 'REJECTED'
  provenance TEXT NOT NULL,
  consent_given INTEGER NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL
);

-- Performance Indexes
CREATE INDEX IF NOT EXISTS idx_posts_category ON community_posts(category);
CREATE INDEX IF NOT EXISTS idx_posts_status ON community_posts(verification_status);
CREATE INDEX IF NOT EXISTS idx_posts_created ON community_posts(created_at);
CREATE INDEX IF NOT EXISTS idx_votes_post ON post_votes(post_id);
CREATE INDEX IF NOT EXISTS idx_comments_post ON comments(post_id);
CREATE INDEX IF NOT EXISTS idx_test_runs_status ON test_runs(status);
CREATE INDEX IF NOT EXISTS idx_test_cases_run ON test_cases(test_run_id);
`;
