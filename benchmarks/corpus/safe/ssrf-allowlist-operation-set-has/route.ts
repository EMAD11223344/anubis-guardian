const HOSTS = new Set(["api.github.com"]);

export async function GET(req: Request) {
  const t = req.nextUrl.searchParams.get("t") ?? "";
  if (!HOSTS.has(new URL(t).hostname)) {
    return Response.json({ error: "host not allowed" }, { status: 400 });
  }
  const r = await fetch(t);
  return new Response(await r.text());
}
