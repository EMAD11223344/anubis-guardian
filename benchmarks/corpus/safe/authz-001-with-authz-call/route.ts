import { getSession } from "@/auth";
import { prisma } from "@/db";
export async function POST(req: Request) {
  const s = await getSession();
  await prisma.user.update({ where: { id: s.userId }, data: { theme: "dark" } });
  return NextResponse.json({ ok: true });
}
