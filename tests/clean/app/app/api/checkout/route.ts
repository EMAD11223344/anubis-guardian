import { NextRequest, NextResponse } from 'next/server';
import { auth } from '@/lib/auth';

// clean cases: AUTH-001 (in-file auth present) + MASS-001 (explicit field mapping)
export async function POST(req: NextRequest) {
  const session = await auth();
  if (!session?.user) return NextResponse.json({ error: 'unauthorized' }, { status: 401 });

  const body = await req.json();
  // explicit whitelist — only known fields reach the write
  const dto = { item: String(body.item ?? ''), qty: Number(body.qty ?? 1) };
  return NextResponse.json({ ok: true, received: dto.item });
}
