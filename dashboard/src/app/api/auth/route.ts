import { NextRequest, NextResponse } from 'next/server';
import { AuthService } from '@/lib/auth';
import { getDatabase } from '@/lib/db';

export async function GET(req: NextRequest) {
  try {
    const user = await AuthService.getCurrentUser(req);
    if (!user) {
      return NextResponse.json({ authenticated: false, user: null }, { status: 200 });
    }
    return NextResponse.json({ authenticated: true, user }, { status: 200 });
  } catch (error: any) {
    return NextResponse.json({ error: error.message }, { status: 500 });
  }
}

export async function POST(req: NextRequest) {
  try {
    const body = await req.json();
    const { action, username, email, password } = body;

    if (action === 'logout') {
      const response = NextResponse.json({ success: true, message: 'Logged out successfully' });
      response.cookies.delete('scamshield_session');
      return response;
    }

    if (action === 'register') {
      if (!username || !email || !password) {
        return NextResponse.json({ error: 'Username, email and password are required' }, { status: 400 });
      }

      if (password.length < 8) {
        return NextResponse.json({ error: 'Password must be at least 8 characters' }, { status: 400 });
      }

      const user = await AuthService.register(username, email, password);
      const session = await AuthService.createSession(user.id);

      const response = NextResponse.json({
        success: true,
        user: { id: user.id, username: user.username, email: user.email, role: user.role, trustScore: user.trust_score },
      });

      response.cookies.set('scamshield_session', session.token, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'lax',
        path: '/',
        maxAge: 7 * 24 * 60 * 60,
      });

      return response;
    }

    if (action === 'login') {
      if (!email || !password) {
        return NextResponse.json({ error: 'Email/username and password are required' }, { status: 400 });
      }

      const user = await AuthService.authenticate(email, password);
      if (!user) {
        return NextResponse.json({ error: 'Invalid email or password' }, { status: 401 });
      }

      const session = await AuthService.createSession(user.id);

      const response = NextResponse.json({
        success: true,
        user: { id: user.id, username: user.username, email: user.email, role: user.role, trustScore: user.trust_score },
      });

      response.cookies.set('scamshield_session', session.token, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'lax',
        path: '/',
        maxAge: 7 * 24 * 60 * 60,
      });

      return response;
    }

    return NextResponse.json({ error: 'Invalid action. Supported: login, register, logout' }, { status: 400 });
  } catch (error: any) {
    return NextResponse.json({ error: error.message || 'Authentication error' }, { status: 400 });
  }
}
