const { PrismaClient } = require('@prisma/client');
const bcrypt = require('bcrypt');

const prisma = new PrismaClient();

async function main() {
  console.log('Seeding fresh database with requested user accounts...');

  const saltRounds = 12;
  const passwordHash = await bcrypt.hash('password123', saltRounds);

  // 1. Create Default Client Organization
  const clientOrg = await prisma.organization.create({
    data: {
      name: 'Zyron Client Org',
      tier: 'enterprise',
      billingEmail: 'billing@zyron.labs',
    },
  });
  console.log('Created Organization:', clientOrg.name);

  // 2. Admin Account: admin@zyron.labs
  const admin = await prisma.user.create({
    data: {
      email: 'admin@zyron.labs',
      passwordHash: passwordHash,
      name: 'Zyron Admin',
      role: 'ADMIN',
      auditorHandle: '0xAdmin_Root',
      emailVerified: true,
      emailVerifiedAt: new Date(),
      onboardingStatus: 'ACTIVE',
      isAvailable: true,
    },
  });
  console.log('Created Admin:', admin.email);

  // 3. Auditor Account: auditor@zyron.labs
  const auditor = await prisma.user.create({
    data: {
      email: 'auditor@zyron.labs',
      passwordHash: passwordHash,
      name: 'Zyron Auditor',
      role: 'AUDITOR',
      auditorHandle: '0xAuditor_K4',
      specialization: 'EVM & DeFi Protocols',
      emailVerified: true,
      emailVerifiedAt: new Date(),
      onboardingStatus: 'ACTIVE',
      isAvailable: true,
    },
  });
  console.log('Created Auditor:', auditor.email);

  // 4. Client Account: client@zyron.labs
  const client = await prisma.user.create({
    data: {
      email: 'client@zyron.labs',
      passwordHash: passwordHash,
      name: 'Zyron Client',
      role: 'CLIENT',
      organizationId: clientOrg.id,
      emailVerified: true,
      emailVerifiedAt: new Date(),
      onboardingStatus: 'ACTIVE',
      isAvailable: true,
    },
  });
  console.log('Created Client:', client.email);

  console.log('Database reset & seed complete! Only the 3 requested accounts exist with password: password123');
}

main()
  .catch((e) => {
    console.error('Seed error:', e);
    process.exit(1);
  })
  .finally(async () => {
    await prisma.$disconnect();
  });
