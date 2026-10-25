import { PrismaClient } from '@prisma/client';
const db = new PrismaClient();

const adminPassword = process.env.SEED_ADMIN_PASSWORD;
if (!adminPassword) throw new Error('SEED_ADMIN_PASSWORD required — never hardcode seed credentials');

async function main() {
  await db.user.create({
    data: { email: 'admin@clean.io', name: 'Admin', password: adminPassword, role: 'admin' },
  });
}
main();
