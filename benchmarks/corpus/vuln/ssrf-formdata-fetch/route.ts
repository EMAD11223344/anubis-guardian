export async function POST(request: Request) {
  const form = await request.formData();
  const target = form.get("target") as string;
  const r = await fetch(target);
  return new Response(await r.text());
}
