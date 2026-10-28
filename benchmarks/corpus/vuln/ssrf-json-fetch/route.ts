export async function POST(request: Request) {
  const body = await request.json();
  const response = await fetch(body.url);
  return Response.json({ ok: true });
}
