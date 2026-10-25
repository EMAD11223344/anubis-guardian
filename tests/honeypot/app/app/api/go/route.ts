import { NextRequest, NextResponse } from 'next/server';

// honeypot seed: TAINT-002 — user-controlled redirect target (open redirect):
// /api/go?to=https://evil.example steals the click and any ref/token in it.
export async function GET(req: NextRequest) {
  const to = req.nextUrl.searchParams.get('to') ?? '/';
  return NextResponse.redirect(to);
}
