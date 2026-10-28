import Stripe from "stripe";

const stripe = new Stripe(process.env.STRIPE_SECRET_KEY as string);

export async function POST(request: Request) {
  const body = await request.text();
  const sig = request.headers.get("stripe-signature") as string;
  let event;
  try {
    event = stripe.webhooks.constructEvent(body, sig, process.env.STRIPE_WEBHOOK_SECRET as string);
  } catch {
    return new Response("bad signature", { status: 400 });
  }
  await db.payment.update({ where: { id: 1 }, data: { status: event.type } });
  return Response.json({ ok: true });
}
