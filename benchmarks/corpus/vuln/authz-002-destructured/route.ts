export async function POST(request: Request) {
  const { role } = await request.json();
  if (role === 'admin') promoteUser();
  return Response.json({ ok: true });
}
