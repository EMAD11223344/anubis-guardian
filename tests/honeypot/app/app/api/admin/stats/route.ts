import { NextRequest, NextResponse } from 'next/server';

// honeypot seed: AUTH-001 — mutating admin endpoint outside the middleware
// matcher and with no in-file auth check: anyone can read platform stats.
export async function POST(req: NextRequest) {
  const stats = { users: 4120, revenue: '18k/mo', churn: '2.1%' };
  return NextResponse.json({ stats });
}
