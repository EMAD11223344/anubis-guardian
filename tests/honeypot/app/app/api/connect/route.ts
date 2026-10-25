import { Pool } from 'pg';
import { headers } from 'next/headers';

const pool = new Pool({ max: 5 });

export async function POST(req: Request) {
  const dbPassword = req.headers.get('x-db-connection-password') ?? '';
  const dbUser = req.headers.get('x-db-user') ?? 'admin';
  pool.options.password = dbPassword;
  pool.options.user = dbUser;
  const r = await pool.query('SELECT count(*) FROM users');
  return Response.json({ count: r.rows[0] });
}
