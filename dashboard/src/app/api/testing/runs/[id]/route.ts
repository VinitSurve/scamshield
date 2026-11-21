import { NextRequest, NextResponse } from 'next/server';
import { getDatabase } from '@/lib/db';

export async function GET(
  _req: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  try {
    const { id } = await params;
    const db = getDatabase();

    // Query either by primary id or by human-readable run_id
    const run: any = db.prepare(`
      SELECT 
        r.*, u.username as triggered_by
      FROM test_runs r
      LEFT JOIN users u ON r.user_id = u.id
      WHERE r.id = ? OR r.run_id = ?
    `).get(id, id);

    if (!run) {
      return NextResponse.json({ error: 'Test run not found' }, { status: 404 });
    }

    const testCases: any[] = db.prepare(`
      SELECT 
        id, sample_id, content, content_type, language, category,
        attack_type, expected_label, predicted_label, scam_probability,
        passed, latency_ms
      FROM test_cases
      WHERE test_run_id = ?
      ORDER BY id ASC
    `).all(run.id);

    const metrics = JSON.parse(run.metrics_json || '{}');

    return NextResponse.json({
      success: true,
      run: {
        ...run,
        metrics,
      },
      testCases,
    });
  } catch (error: any) {
    return NextResponse.json({ error: error.message }, { status: 500 });
  }
}
