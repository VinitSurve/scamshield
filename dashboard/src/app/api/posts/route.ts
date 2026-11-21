import { NextRequest, NextResponse } from 'next/server';
import { getDatabase } from '@/lib/db';
import { AuthService } from '@/lib/auth';
import { RedactionService } from '@/lib/auth/privacy';
import { RateLimiter } from '@/lib/auth/rate-limit';
import { ScamShieldScanner } from '@/lib/analysis/scanner';
import { randomUUID } from 'crypto';

export async function GET(req: NextRequest) {
  try {
    const db = getDatabase();
    const url = new URL(req.url);

    const category = url.searchParams.get('category');
    const status = url.searchParams.get('status');
    const severity = url.searchParams.get('severity');
    const search = url.searchParams.get('search');
    const page = Math.max(1, parseInt(url.searchParams.get('page') || '1', 10));
    const limit = Math.min(50, Math.max(1, parseInt(url.searchParams.get('limit') || '15', 10)));
    const offset = (page - 1) * limit;

    const conditions: string[] = [];
    const params: any[] = [];

    if (category && category !== 'ALL') {
      conditions.push('p.category = ?');
      params.push(category);
    }

    if (status && status !== 'ALL') {
      conditions.push('p.verification_status = ?');
      params.push(status);
    }

    if (severity && severity !== 'ALL') {
      conditions.push('p.severity = ?');
      params.push(severity);
    }

    if (search) {
      conditions.push('(p.title LIKE ? OR p.description LIKE ? OR p.content LIKE ?)');
      params.push(`%${search}%`, `%${search}%`, `%${search}%`);
    }

    const whereClause = conditions.length > 0 ? `WHERE ${conditions.join(' AND ')}` : '';

    const countRow: any = db.prepare(`
      SELECT COUNT(*) as total FROM community_posts p ${whereClause}
    `).get(...params);

    const total = countRow?.total || 0;

    const posts = db.prepare(`
      SELECT 
        p.id, p.user_id, p.title, p.description, p.category, p.scam_type,
        p.language, p.platform, p.severity, p.content, p.extracted_indicators,
        p.verification_status, p.upvotes, p.downvotes, p.view_count, p.tags,
        p.created_at, u.username as author_username, u.trust_score as author_trust_score
      FROM community_posts p
      JOIN users u ON p.user_id = u.id
      ${whereClause}
      ORDER BY p.created_at DESC
      LIMIT ? OFFSET ?
    `).all(...params, limit, offset);

    // Parse JSON fields
    const formatted = (posts as any[]).map((post) => ({
      ...post,
      extracted_indicators: JSON.parse(post.extracted_indicators || '[]'),
      tags: JSON.parse(post.tags || '[]'),
    }));

    return NextResponse.json({
      success: true,
      page,
      limit,
      total,
      totalPages: Math.ceil(total / limit),
      posts: formatted,
    });
  } catch (error: any) {
    return NextResponse.json({ error: error.message }, { status: 500 });
  }
}

export async function POST(req: NextRequest) {
  try {
    // 1. Authenticate user
    const user = await AuthService.getCurrentUser(req);
    if (!user) {
      return NextResponse.json({ error: 'You must be logged in to submit a report' }, { status: 401 });
    }

    // 2. Rate limit per user
    const rateCheck = RateLimiter.check(`post:${user.id}`, 10, 60 * 1000);
    if (!rateCheck.allowed) {
      return NextResponse.json(
        { error: `Too many submissions. Try again in ${Math.ceil(rateCheck.retryAfter / 1000)}s` },
        { status: 429 }
      );
    }

    // 3. Parse input
    const body = await req.json();
    const { title, description, content, category, platform, language, tags } = body;

    if (!title || !content) {
      return NextResponse.json({ error: 'Title and content are required' }, { status: 400 });
    }

    // 4. PII Redaction for citizen privacy
    const redactedContent = RedactionService.redactPII(content);
    const redactedDesc = RedactionService.redactPII(description || '');

    // 5. Run automatic ScamShield analysis
    const scan = await ScamShieldScanner.scanText(content, platform || 'SMS', language || 'en');

    const db = getDatabase();
    const postId = randomUUID();
    const postCategory = category || scan.category || 'OTHER';
    const postSeverity = scan.riskClassification;

    // Combine extracted entities as indicators
    const indicators: string[] = [
      ...scan.extractedEntities.urls,
      ...scan.extractedEntities.phones,
      ...scan.extractedEntities.upiIds,
      ...scan.socialTactics,
    ];

    const tagsJson = JSON.stringify(Array.isArray(tags) ? tags : [postCategory, platform || 'SMS']);
    const indicatorsJson = JSON.stringify(indicators);

    // Initial verification status based on confidence
    let verificationStatus = 'UNVERIFIED';
    if (scan.riskScore >= 90) {
      verificationStatus = 'COMMUNITY_SUPPORTED';
    }

    db.prepare(`
      INSERT INTO community_posts (
        id, user_id, title, description, category, scam_type, language,
        platform, severity, content, extracted_indicators, verification_status,
        upvotes, downvotes, view_count, tags, is_redacted, created_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, 0, 1, ?, 1, datetime('now'))
    `).run(
      postId,
      user.id,
      title.trim(),
      redactedDesc.trim(),
      postCategory,
      scan.category,
      language || 'en',
      platform || 'SMS',
      postSeverity,
      redactedContent.trim(),
      indicatorsJson,
      verificationStatus,
      tagsJson
    );

    // Auto-create benchmark contribution candidate
    db.prepare(`
      INSERT INTO benchmark_contributions (
        id, post_id, user_id, content, suggested_label, category, language,
        status, provenance, consent_given, created_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, 'SUBMITTED', 'COMMUNITY_SUBMISSION', 1, datetime('now'))
    `).run(
      randomUUID(),
      postId,
      user.id,
      redactedContent.trim(),
      scan.riskScore >= 50 ? 'SCAM' : 'LEGITIMATE',
      postCategory,
      language || 'en'
    );

    return NextResponse.json({
      success: true,
      postId,
      verificationStatus,
      analysis: {
        riskScore: scan.riskScore,
        riskClassification: scan.riskClassification,
        tactics: scan.socialTactics,
        recommendations: scan.securityRecommendations,
      },
      message: 'Report submitted and analyzed successfully',
    });
  } catch (error: any) {
    return NextResponse.json({ error: error.message }, { status: 500 });
  }
}
