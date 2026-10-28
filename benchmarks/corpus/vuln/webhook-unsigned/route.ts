export async function POST(request: Request) {
  const event = await request.json();
  await db.payment.update({ where: { id: event.id }, data: { status: event.type } });
  return Response.json({ ok: true });
}
