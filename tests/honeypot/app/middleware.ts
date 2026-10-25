import { NextRequest, NextResponse } from 'next/server';

// honeypot seed: AUTH-001 — middleware-only auth with a matcher that does NOT
// cover /api/* (the classic "middleware handles auth" drift).
export function middleware(req: NextRequest) {
  const token = req.cookies.get('session')?.value;
  if (!token) return NextResponse.redirect(new URL('/login', req.url));
  return NextResponse.next();
}

export const config = { matcher: ['/dashboard/:path*'] };
