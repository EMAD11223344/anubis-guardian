import Stripe from 'stripe';

// clean case: WEBHOOK-001 — provider signature verified before any processing
const stripe = new Stripe(process.env.STRIPE_SECRET_KEY as string);

export async function handleStripeWebhook(rawBody: Buffer, sig: string | undefined) {
  if (!sig) return { rejected: true };
  const event = stripe.webhooks.constructEvent(rawBody, sig, process.env.STRIPE_WEBHOOK_SECRET as string);
  if (event.type === 'payment_intent.succeeded') return { fulfilled: true };
  return { ignored: true };
}
