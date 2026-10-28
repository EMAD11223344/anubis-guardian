export async function POST(request: Request) {
  const body = await request.json();
  const re = new RegExp(body.pattern);
  return Response.json({ matched: re.test("x") });
}
