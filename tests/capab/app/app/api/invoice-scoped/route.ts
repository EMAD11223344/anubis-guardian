import { prisma } from "@/db";
export async function DELETE(req: Request) {
  await prisma.invoice.delete({ where: { id: req.params.id, organizationId: session.orgId } });
  return NextResponse.json({ ok: true });
}
