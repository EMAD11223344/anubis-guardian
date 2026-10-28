export async function POST(request: Request) {
  const body = await request.json();
  const u = await db.user.findUnique({ where: { id: sess.userId } });
  if (u.role === 'admin') grantAdmin();
  return Response.json({ ok: true });
}
