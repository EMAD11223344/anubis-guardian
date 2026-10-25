import { NextRequest, NextResponse } from 'next/server';

// honeypot seed: TAINT-001 — user-controlled URL straight into fetch (SSRF):
// the server can be pointed at internal services / cloud metadata endpoints.
export async function GET(req: NextRequest) {
  const target = req.nextUrl.searchParams.get('url') ?? '';
  const upstream = await fetch(target);
  const text = await upstream.text();
  return new NextResponse(text);
}
