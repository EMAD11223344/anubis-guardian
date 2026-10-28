export async function POST(request: Request) {
  const body = await request.json();
  const response = await fetch("https://api.example.com/hook", { signal: AbortSignal.timeout(5000) });
  return Response.json({ ok: true });
}
