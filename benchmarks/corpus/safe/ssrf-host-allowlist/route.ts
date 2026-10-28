export async function POST(request: Request) {
  const body = await request.json();
  const target = body.url;
  if (!ALLOWED_HOSTS.includes(new URL(target).host)) {
    return Response.json({ error: "host not allowed" }, { status: 400 });
  }
  const r = await fetch(target, { signal: AbortSignal.timeout(5000) });
}
