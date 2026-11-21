import { NextRequest, NextResponse } from 'next/server';
import { getDatabase } from '@/lib/db';
import { AuthService } from '@/lib/auth';
import { RedactionService } from '@/lib/auth/privacy';
import { randomUUID } from 'crypto';

export async function POST(
  req: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  try {
    const { id: postId } = await params;
    const user = await AuthService.getCurrentUser(req);
    if (!user) {
      return NextResponse.json({ error: 'You must be logged in to comment' }, { status: 401 });
    }

    const body = await req.json();
    const { content, parentId } = body;

    if (!content || !content.trim()) {
      return NextResponse.json({ error: 'Comment content cannot be empty' }, { status: 400 });
    }

    // Redact PII in user comments
    const redactedContent = RedactionService.redactPII(content.trim());
    const db = getDatabase();

    const commentId = randomUUID();
    db.prepare(`
      INSERT INTO comments (id, post_id, user_id, parent_id, content, created_at)
      VALUES (?, ?, ?, ?, ?, datetime('now'))
    `).run(commentId, postId, user.id, parentId || null, redactedContent);

    return NextResponse.json({
      success: true,
      comment: {
        id: commentId,
        content: redactedContent,
        author_username: user.username,
        author_trust_score: user.trust_score,
        created_at: new Date().toISOString(),
      },
    });
  } catch (error: any) {
    return NextResponse.json({ error: error.message }, { status: 500 });
  }
}
