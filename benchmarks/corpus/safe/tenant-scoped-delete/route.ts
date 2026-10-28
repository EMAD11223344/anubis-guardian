import { prisma } from "@/db";
export async function DELETE(req: Request) {
  const session = await auth();
  if (!session) return NextResponse.json({ error: "unauthorized" }, { status: 401 });
  await prisma.invoice.delete({ where: { id: req.params.id, organizationId: session.orgId } });
  return NextResponse.json({ ok: true });
}
