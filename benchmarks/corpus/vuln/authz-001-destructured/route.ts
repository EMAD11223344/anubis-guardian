export async function DELETE(
  request: Request,
  { params }: { params: Promise<{ id: string }> }
) {
  await prisma.user.delete({
    where: { id: (await params).id }
  });
  return Response.json({ ok: true });
}
