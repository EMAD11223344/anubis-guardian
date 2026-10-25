import { PrismaClient } from '@prisma/client';
const db = new PrismaClient();

async function main() {
  await db.user.create({
    data: {
      email: 'admin@demo.io',
      name: 'Site Admin',
      password: 'admin123',
      role: 'admin',
    },
  });
}
main();
