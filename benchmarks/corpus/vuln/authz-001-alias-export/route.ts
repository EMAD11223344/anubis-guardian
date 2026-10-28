import { NextResponse } from "next/server";

const handler = async function (request: Request) {
  const data = await request.json();
  await prisma.user.delete({ where: { id: data.id } });
  return NextResponse.json({ ok: true });
};

export { handler as DELETE };
