import { prisma } from "@/db";
export async function DELETE(req: Request) {
  await prisma.invoice.delete({ where: { id: req.params.id } });
  return NextResponse.json({ ok: true });
}
