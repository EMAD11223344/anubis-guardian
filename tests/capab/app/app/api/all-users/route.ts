export async function GET() {
  const rows = await prisma.user.findMany();
  return NextResponse.json(rows);
}
