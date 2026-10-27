import { prisma } from "@/db";
export async function POST(req: Request) {
  const data = await req.json();
  await prisma.user.update({ where: { id: data.id }, data: { role: data.role } });
  return NextResponse.json({ ok: true });
}
