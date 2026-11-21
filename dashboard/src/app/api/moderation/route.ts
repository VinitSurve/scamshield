import { NextRequest, NextResponse } from 'next/server';
import { getDatabase } from '@/lib/db';
import { AuthService } from '@/lib/auth';
import { randomUUID } from 'crypto';

export async function GET(req: NextRequest) {
  try {
    const user = await AuthService.getCurrentUser(req);
    if (!user || (user.role !== 'moderator' && user.role !== 'admin')) {
      return NextResponse.json({ error: 'Unauthorized: Moderator access required' }, { status: 403 });
    }

    const db = getDatabase();

    const pendingPosts: any[] = db.prepare(`
      SELECT 
        p.id, p.title, p.category, p.severity, p.verification_status,
        p.content, p.upvotes, p.downvotes, p.created_at, u.username as author_username
      FROM community_posts p
      JOIN users u ON p.user_id = u.id
      WHERE p.verification_status IN ('UNVERIFIED', 'UNDER_REVIEW')
      ORDER BY p.created_at DESC
      LIMIT 30
    `).all();

    const reports: any[] = db.prepare(`
      SELECT 
        r.id, r.target_type, r.target_id, r.reason, r.status, r.created_at,
        u.username as reporter_username
      FROM reports r
      JOIN users u ON r.reporter_user_id = u.id
      WHERE r.status = 'PENDING'
      ORDER BY r.created_at DESC
      LIMIT 30
    `).all();

    const benchmarkCandidates: any[] = db.prepare(`
      SELECT 
        b.id, b.content, b.suggested_label, b.category, b.language, b.status,
        b.created_at, u.username as contributor_username
      FROM benchmark_contributions b
      JOIN users u ON b.user_id = u.id
      WHERE b.status = 'SUBMITTED'
      ORDER BY b.created_at DESC
      LIMIT 30
    `).all();

    return NextResponse.json({
      success: true,
      pendingPosts,
      reports,
      benchmarkCandidates,
    });
  } catch (error: any) {
    return NextResponse.json({ error: error.message }, { status: 500 });
  }
}

export async function POST(req: NextRequest) {
  try {
    const user = await AuthService.getCurrentUser(req);
    if (!user || (user.role !== 'moderator' && user.role !== 'admin')) {
      return NextResponse.json({ error: 'Unauthorized: Moderator access required' }, { status: 403 });
    }

    const body = await req.json();
    const { actionType, targetType, targetId, notes } = body;

    const db = getDatabase();

    if (actionType === 'VERIFY_POST') {
      db.prepare(`UPDATE community_posts SET verification_status = 'VERIFIED' WHERE id = ?`).run(targetId);
    } else if (actionType === 'FLAG_FALSE_REPORT') {
      db.prepare(`UPDATE community_posts SET verification_status = 'FALSE_REPORT' WHERE id = ?`).run(targetId);
    } else if (actionType === 'RESOLVE_POST') {
      db.prepare(`UPDATE community_posts SET verification_status = 'RESOLVED' WHERE id = ?`).run(targetId);
    } else if (actionType === 'DELETE_POST') {
      db.prepare(`DELETE FROM community_posts WHERE id = ?`).run(targetId);
    } else if (actionType === 'APPROVE_BENCHMARK') {
      db.prepare(`UPDATE benchmark_contributions SET status = 'BENCHMARK_ELIGIBLE' WHERE id = ?`).run(targetId);
    } else if (actionType === 'REJECT_BENCHMARK') {
      db.prepare(`UPDATE benchmark_contributions SET status = 'REJECTED' WHERE id = ?`).run(targetId);
    }

    // Record moderation action audit
    db.prepare(`
      INSERT INTO moderation_actions (id, moderator_user_id, target_type, target_id, action_type, notes, created_at)
      VALUES (?, ?, ?, ?, ?, ?, datetime('now'))
    `).run(
      randomUUID(),
      user.id,
      targetType || 'post',
      targetId,
      actionType,
      notes || null
    );

    return NextResponse.json({
      success: true,
      message: `Moderation action '${actionType}' completed successfully`,
    });
  } catch (error: any) {
    return NextResponse.json({ error: error.message }, { status: 500 });
  }
}
