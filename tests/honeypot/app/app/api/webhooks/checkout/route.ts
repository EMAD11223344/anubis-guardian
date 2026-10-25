import { NextRequest, NextResponse } from 'next/server';

// honeypot seed: WEBHOOK-001 — payment webhook processed without signature
// verification: anyone who finds the URL can forge "payment.succeeded".
export async function POST(req: NextRequest) {
  const event = await req.json();
  if (event.type === 'payment.succeeded') {
    await fetch('https://internal.example/fulfill', {
      method: 'POST',
      body: JSON.stringify({ orderId: event.data.orderId }),
    });
  }
  return NextResponse.json({ received: true });
}
