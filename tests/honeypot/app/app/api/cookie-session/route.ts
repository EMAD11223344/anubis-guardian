import { NextRequest, NextResponse } from 'next/server';
import { cookies } from 'next/headers';

// honeypot seed: NEXT-005 — cookie-authenticated mutating endpoint with no
// CSRF defense signal (heuristic): a cross-site form can drive this POST.
export async function POST(req: NextRequest) {
  const session = cookies().get('session')?.value;
  if (!session) return NextResponse.json({ error: 'unauthorized' }, { status: 401 });
  return NextResponse.json({ transferred: true });
}
