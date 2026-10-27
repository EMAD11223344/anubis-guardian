export async function GET() {
  const u = await db.users.findFirst();
  return NextResponse.json({ name: u.name, password: undefined });
}
