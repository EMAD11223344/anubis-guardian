export async function POST(request: Request) {
  const { url } = await request.json();
  await fetch(url);
}
