import { exec } from 'node:child_process';
import { NextRequest, NextResponse } from 'next/server';

// honeypot seed: TAINT-004 — query param interpolated into a shell command
// (command injection): ?name=x;rm+-rf+/ runs inside the container.
export async function GET(req: NextRequest) {
  const name = req.nextUrl.searchParams.get('name') ?? 'input';
  exec(`convert ${name} out.png`);
  return NextResponse.json({ ok: true });
}
