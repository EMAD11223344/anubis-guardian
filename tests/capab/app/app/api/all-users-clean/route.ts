export async function GET() {
  const rows = await prisma.user.findMany({ take: 25 });
  return NextResponse.json(rows);
}
