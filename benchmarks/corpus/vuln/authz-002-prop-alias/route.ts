export async function POST(request: Request) {
  const data = await request.json();
  const r = data.role;
  switch (r) {
    case "admin":
      await prisma.user.delete({ where: { id: data.id } });
  }
  return Response.json({ ok: true });
}
