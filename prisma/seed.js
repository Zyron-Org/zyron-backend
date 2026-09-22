const { PrismaClient } = require('@prisma/client');
const bcrypt = require('bcrypt');

const prisma = new PrismaClient();

async function main() {
  console.log('Seeding initial database test accounts...');

  const saltRounds = 12;

  // Create Aura Protocol organization
  let auraOrg = await prisma.organization.findFirst({
    where: { name: 'Aura Protocol' },
  });

  if (!auraOrg) {
    auraOrg = await prisma.organization.create({
      data: {
        name: 'Aura Protocol',
        tier: 'enterprise',
        billingEmail: 'billing@auraprotocol.io',
      },
    });
    console.log('Created organization: Aura Protocol');
  }

  // 1. Auditor Account
  const auditorPassHash = await bcrypt.hash('AuditorPass123!', saltRounds);
  await prisma.user.upsert({
    where: { email: 'k4@zyron.labs' },
    update: {
      passwordHash: auditorPassHash,
      role: 'AUDITOR',
      auditorHandle: '0xAuditor_K4',
      emailVerified: true,
      onboardingStatus: 'ACTIVE',
    },
    create: {
      email: 'k4@zyron.labs',
      passwordHash: auditorPassHash,
      name: 'K4 Auditor',
      role: 'AUDITOR',
      auditorHandle: '0xAuditor_K4',
      specialization: 'EVM & DeFi Protocols',
      isAvailable: true,
      emailVerified: true,
      emailVerifiedAt: new Date(),
      onboardingStatus: 'ACTIVE',
    },
  });
  console.log('Upserted Auditor: k4@zyron.labs');

  // 2. Admin Account
  const adminPassHash = await bcrypt.hash('AdminPass123!', saltRounds);
  await prisma.user.upsert({
    where: { email: 'admin@zyron.labs' },
    update: {
      passwordHash: adminPassHash,
      role: 'ADMIN',
      auditorHandle: '0xAdmin_Root',
      emailVerified: true,
      onboardingStatus: 'ACTIVE',
    },
    create: {
      email: 'admin@zyron.labs',
      passwordHash: adminPassHash,
      name: 'Zyron System Admin',
      role: 'ADMIN',
      auditorHandle: '0xAdmin_Root',
      emailVerified: true,
      emailVerifiedAt: new Date(),
      onboardingStatus: 'ACTIVE',
    },
  });
  console.log('Upserted Admin: admin@zyron.labs');

  // 3. Client Account
  const clientPassHash = await bcrypt.hash('SecurePassword123!', saltRounds);
  await prisma.user.upsert({
    where: { email: 'security@auraprotocol.io' },
    update: {
      passwordHash: clientPassHash,
      role: 'CLIENT',
      auditorHandle: 'AuraSecurity',
      organizationId: auraOrg.id,
      emailVerified: true,
      onboardingStatus: 'ACTIVE',
    },
    create: {
      email: 'security@auraprotocol.io',
      passwordHash: clientPassHash,
      name: 'Aura Security Lead',
      role: 'CLIENT',
      auditorHandle: 'AuraSecurity',
      organizationId: auraOrg.id,
      emailVerified: true,
      emailVerifiedAt: new Date(),
      onboardingStatus: 'ACTIVE',
    },
  });
  console.log('Upserted Client: security@auraprotocol.io');

  console.log('Database seeding finished successfully!');
}

main()
  .catch((e) => {
    console.error('Seed error:', e);
    process.exit(1);
  })
  .finally(async () => {
    await prisma.$disconnect();
  });
