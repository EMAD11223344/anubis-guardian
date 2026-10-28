const ALLOWED_HOSTS = ["api.github.com"];

export async function GET(req: Request) {
  const target = req.nextUrl.searchParams.get("target") ?? "";
  // ALLOWED_HOSTS is declared but never applied to the destination below —
  // a name alone is not a validation operation.
  const r = await fetch(target);
  return new Response(await r.text());
}
