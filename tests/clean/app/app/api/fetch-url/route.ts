import { NextRequest, NextResponse } from 'next/server';

// clean case: TAINT-001 — outbound requests restricted to a host allowlist
const ALLOWED_HOSTS = ['api.github.com', 'api.example.com'];

export async function GET(req: NextRequest) {
  const target = req.nextUrl.searchParams.get('url') ?? '';
  let host = '';
  try { host = new URL(target).host; } catch { return NextResponse.json({ error: 'bad url' }, { status: 400 }); }
  if (!ALLOWED_HOSTS.includes(host)) return NextResponse.json({ error: 'host not allowed' }, { status: 400 });
  const upstream = await fetch(target);
  return new NextResponse(await upstream.text());
}
