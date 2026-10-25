import { NextRequest, NextResponse } from 'next/server';

// clean case: TAINT-002 — only same-origin relative redirects are allowed
export async function GET(req: NextRequest) {
  const to = req.nextUrl.searchParams.get('to') ?? '/';
  if (!to.startsWith('/') || to.startsWith('//')) {
    return NextResponse.json({ error: 'invalid redirect target' }, { status: 400 });
  }
  return NextResponse.redirect(new URL(to, req.url));
}
