import { NextRequest, NextResponse } from 'next/server';
import { TestingMatrixEngine } from '@/lib/testing/matrix';
import { getDatabase } from '@/lib/db';
import { AuthService } from '@/lib/auth';

export async function GET(req: NextRequest) {
  try {
    const db = getDatabase();
    const url = new URL(req.url);
    const limit = Math.min(50, parseInt(url.searchParams.get('limit') || '20', 10));

    const runs: any[] = db.prepare(`
      SELECT 
        r.id, r.run_id, r.model_name, r.dataset_version, r.test_profile,
        r.sample_count, r.status, r.accuracy, r.precision, r.recall,
        r.f1_score, r.fpr, r.created_at, u.username as triggered_by
      FROM test_runs r
      LEFT JOIN users u ON r.user_id = u.id
      ORDER BY r.created_at DESC
      LIMIT ?
    `).all(limit);

    return NextResponse.json({
      success: true,
      runs,
    });
  } catch (error: any) {
    return NextResponse.json({ error: error.message }, { status: 500 });
  }
}

export async function POST(req: NextRequest) {
  try {
    const user = await AuthService.getCurrentUser(req);
    const body = await req.json().catch(() => ({}));
    const profile = (body.profile || 'STANDARD').toUpperCase();
    const modelName = body.modelName || 'ScamShield-Ensemble-v3';

    const validProfiles = ['QUICK', 'STANDARD', 'FULL', 'ADVERSARIAL', 'LANGUAGE', 'DOCUMENT', 'REGRESSION', 'URL'];
    if (!validProfiles.includes(profile)) {
      return NextResponse.json(
        { error: `Invalid profile: ${profile}. Valid: ${validProfiles.join(', ')}` },
        { status: 400 }
      );
    }

    // Execute the testing matrix
    const summary = await TestingMatrixEngine.runMatrix(profile, modelName, user?.id);

    return NextResponse.json({
      success: true,
      summary,
    });
  } catch (error: any) {
    return NextResponse.json({ error: error.message || 'Matrix test execution failed' }, { status: 500 });
  }
}
