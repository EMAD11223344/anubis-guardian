import { Pool } from 'pg';
const pool = new Pool({ connectionString: process.env.DATABASE_URL });

export async function getOrder(id: string) {
  const r = await pool.query('SELECT * FROM orders WHERE id = $1', [id]);
  return r.rows[0] ?? null;
}

export async function callWebhookVerify(payload: string, sig: string) {
  const res = await fetch('https://api.example.com/hook', {
    method: 'POST',
    headers: { 'x-signature': sig, 'content-type': 'application/json' },
    body: payload,
  });
  return res.ok;
}
