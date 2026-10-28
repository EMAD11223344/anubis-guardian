export async function POST(request: Request) {
  const session = await auth();
  if (!session) return Response.json({ error: "unauthorized" }, { status: 401 });
  const body = await request.json();
  if (body.displayName) {
    log(body.displayName);
  }
  await db.event.create({ data: { ref: body.eventId } });
  return Response.json({ received: body.displayName });
}
