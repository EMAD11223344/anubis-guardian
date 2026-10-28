export const DELETE = async (request: Request, context) => {
  await prisma.user.delete({
    where: { id: "123" }
  });
  return Response.json({ ok: true });
};
