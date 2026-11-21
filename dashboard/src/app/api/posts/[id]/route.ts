import { NextRequest, NextResponse } from 'next/server';
import { getDatabase } from '@/lib/db';
import { AuthService } from '@/lib/auth';

export async function GET(
  req: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  try {
    const { id } = await params;
    const db = getDatabase();

    // Increment view count
    db.prepare(`UPDATE community_posts SET view_count = view_count + 1 WHERE id = ?`).run(id);

    const post: any = db.prepare(`
      SELECT 
        p.*, u.username as author_username, u.trust_score as author_trust_score
      FROM community_posts p
      JOIN users u ON p.user_id = u.id
      WHERE p.id = ?
    `).get(id);

    if (!post) {
      return NextResponse.json({ error: 'Post not found' }, { status: 404 });
    }

    // Get current user vote if logged in
    const currentUser = await AuthService.getCurrentUser(req);
    let userVote: string | null = null;
    let isBookmarked = false;

    if (currentUser) {
      const voteRow: any = db.prepare(`
        SELECT vote_type FROM post_votes WHERE post_id = ? AND user_id = ?
      `).get(id, currentUser.id);
      if (voteRow) userVote = voteRow.vote_type;

      const bookmarkRow: any = db.prepare(`
        SELECT id FROM bookmarks WHERE post_id = ? AND user_id = ?
      `).get(id, currentUser.id);
      if (bookmarkRow) isBookmarked = true;
    }

    // Get comments
    const comments: any[] = db.prepare(`
      SELECT 
        c.id, c.content, c.created_at, c.parent_id,
        u.username as author_username, u.trust_score as author_trust_score
      FROM comments c
      JOIN users u ON c.user_id = u.id
      WHERE c.post_id = ?
      ORDER BY c.created_at ASC
    `).all(id);

    return NextResponse.json({
      success: true,
      post: {
        ...post,
        extracted_indicators: JSON.parse(post.extracted_indicators || '[]'),
        tags: JSON.parse(post.tags || '[]'),
        userVote,
        isBookmarked,
      },
      comments,
    });
  } catch (error: any) {
    return NextResponse.json({ error: error.message }, { status: 500 });
  }
}
