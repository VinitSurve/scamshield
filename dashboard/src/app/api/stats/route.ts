import { NextRequest, NextResponse } from 'next/server';
import { getDatabase } from '@/lib/db';

export async function GET(_req: NextRequest) {
  try {
    const db = getDatabase();

    const postStats: any = db.prepare(`
      SELECT 
        COUNT(*) as total_posts,
        SUM(CASE WHEN verification_status = 'VERIFIED' THEN 1 ELSE 0 END) as verified_posts,
        SUM(CASE WHEN severity = 'CRITICAL' THEN 1 ELSE 0 END) as critical_posts,
        SUM(upvotes) as total_upvotes
      FROM community_posts
    `).get() || {};

    const categoryBreakdown: any[] = db.prepare(`
      SELECT category, COUNT(*) as count 
      FROM community_posts 
      GROUP BY category 
      ORDER BY count DESC
    `).all();

    const recentThreats: any[] = db.prepare(`
      SELECT id, title, category, severity, verification_status, created_at, upvotes
      FROM community_posts
      ORDER BY created_at DESC
      LIMIT 6
    `).all();

    const testStats: any = db.prepare(`
      SELECT 
        COUNT(*) as total_runs,
        AVG(accuracy) as avg_accuracy,
        AVG(precision) as avg_precision,
        AVG(recall) as avg_recall,
        AVG(f1_score) as avg_f1,
        AVG(fpr) as avg_fpr
      FROM test_runs
      WHERE status = 'PASSED' OR status = 'FAILED'
    `).get() || {};

    const latestRun: any = db.prepare(`
      SELECT run_id, model_name, test_profile, sample_count, status, accuracy, f1_score, fpr, created_at
      FROM test_runs
      ORDER BY created_at DESC
      LIMIT 1
    `).get();

    return NextResponse.json({
      success: true,
      stats: {
        totalReports: postStats.total_posts || 0,
        verifiedScams: postStats.verified_posts || 0,
        criticalThreats: postStats.critical_posts || 0,
        communityVotes: postStats.total_upvotes || 0,
        categoryBreakdown,
        recentThreats,
        testEngine: {
          totalTestRuns: testStats.total_runs || 0,
          avgAccuracy: Math.round((testStats.avg_accuracy || 0) * 10) / 10,
          avgPrecision: Math.round((testStats.avg_precision || 0) * 10) / 10,
          avgRecall: Math.round((testStats.avg_recall || 0) * 10) / 10,
          avgF1: Math.round((testStats.avg_f1 || 0) * 10) / 10,
          avgFpr: Math.round((testStats.avg_fpr || 0) * 10) / 10,
          latestRun: latestRun || null,
        },
      },
    });
  } catch (error: any) {
    return NextResponse.json({ error: error.message }, { status: 500 });
  }
}
