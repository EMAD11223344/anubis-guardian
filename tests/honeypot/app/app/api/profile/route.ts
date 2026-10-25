import { NextRequest, NextResponse } from 'next/server';
import { supabaseAdmin } from '@/lib/supabase-server';

// honeypot seed: MASS-001 — the parsed request body flows straight into a
// database update with no whitelist: clients can set is_admin, plan, quota…
export async function PATCH(req: NextRequest) {
  const payload = await req.json();
  const { error } = await supabaseAdmin.from('profiles').update(payload).eq('id', 'seed');
  return NextResponse.json({ ok: !error });
}
