export async function POST(request: Request) {
  const body = await request.json();

  if (body.isAdmin) {
    await promoteUser(body.userId);
  }

  return Response.json({ ok: true });
}
