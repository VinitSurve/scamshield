import { NextRequest, NextResponse } from 'next/server';
import { getDatabase } from '@/lib/db';
import { AuthService } from '@/lib/auth';
import { randomUUID } from 'crypto';

export async function POST(
  req: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  try {
    const { id: postId } = await params;
    const user = await AuthService.getCurrentUser(req);
    if (!user) {
      return NextResponse.json({ error: 'You must be logged in to vote' }, { status: 401 });
    }

    const body = await req.json();
    const { voteType } = body; // 'UP' or 'DOWN'

    if (voteType !== 'UP' && voteType !== 'DOWN') {
      return NextResponse.json({ error: 'voteType must be UP or DOWN' }, { status: 400 });
    }

    const db = getDatabase();

    // Check if post exists
    const post: any = db.prepare('SELECT id, upvotes, downvotes FROM community_posts WHERE id = ?').get(postId);
    if (!post) {
      return NextResponse.json({ error: 'Post not found' }, { status: 404 });
    }

    // Check existing vote
    const existingVote: any = db.prepare('SELECT id, vote_type FROM post_votes WHERE post_id = ? AND user_id = ?').get(postId, user.id);

    if (existingVote) {
      if (existingVote.vote_type === voteType) {
        // Toggle/remove vote
        db.prepare('DELETE FROM post_votes WHERE id = ?').run(existingVote.id);
        const col = voteType === 'UP' ? 'upvotes' : 'downvotes';
        db.prepare(`UPDATE community_posts SET ${col} = MAX(0, ${col} - 1) WHERE id = ?`).run(postId);
        return NextResponse.json({ success: true, userVote: null, message: 'Vote removed' });
      } else {
        // Switch vote
        db.prepare('UPDATE post_votes SET vote_type = ?, created_at = datetime(\'now\') WHERE id = ?').run(voteType, existingVote.id);
        if (voteType === 'UP') {
          db.prepare('UPDATE community_posts SET upvotes = upvotes + 1, downvotes = MAX(0, downvotes - 1) WHERE id = ?').run(postId);
        } else {
          db.prepare('UPDATE community_posts SET downvotes = downvotes + 1, upvotes = MAX(0, upvotes - 1) WHERE id = ?').run(postId);
        }
        return NextResponse.json({ success: true, userVote: voteType, message: 'Vote switched' });
      }
    } else {
      // New vote (Vote manipulation prevention: 1 vote per user/post via UNIQUE constraint)
      db.prepare(`
        INSERT INTO post_votes (id, post_id, user_id, vote_type, created_at)
        VALUES (?, ?, ?, ?, datetime('now'))
      `).run(randomUUID(), postId, user.id, voteType);

      const col = voteType === 'UP' ? 'upvotes' : 'downvotes';
      db.prepare(`UPDATE community_posts SET ${col} = ${col} + 1 WHERE id = ?`).run(postId);

      return NextResponse.json({ success: true, userVote: voteType, message: 'Vote recorded' });
    }
  } catch (error: any) {
    return NextResponse.json({ error: error.message }, { status: 500 });
  }
}
