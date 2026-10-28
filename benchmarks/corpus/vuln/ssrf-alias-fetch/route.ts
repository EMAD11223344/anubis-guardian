export async function POST(request: Request) {
  const body = await request.json();
  const target = body.url;
  await fetch(target);
}
