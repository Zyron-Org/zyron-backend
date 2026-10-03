const { PrismaClient } = require('@prisma/client');
const prisma = new PrismaClient();

async function clearAudits() {
  console.log('Clearing audit data while preserving user accounts...');

  const comments = await prisma.comment.deleteMany({});
  console.log('Deleted comments:', comments.count);

  const findings = await prisma.finding.deleteMany({});
  console.log('Deleted findings:', findings.count);

  const scanJobs = await prisma.scanJob.deleteMany({});
  console.log('Deleted scanJobs:', scanJobs.count);

  const scanRuns = await prisma.scanRun.deleteMany({});
  console.log('Deleted scanRuns:', scanRuns.count);

  const rounds = await prisma.auditRound.deleteMany({});
  console.log('Deleted auditRounds:', rounds.count);

  const payments = await prisma.payment.deleteMany({});
  console.log('Deleted payments:', payments.count);

  const audits = await prisma.auditRequest.deleteMany({});
  console.log('Deleted auditRequests:', audits.count);

  const usersCount = await prisma.user.count();
  console.log('Preserved user accounts:', usersCount);

  const users = await prisma.user.findMany({ select: { email: true, role: true } });
  console.log('Users in database:', users);

  await prisma.$disconnect();
}

clearAudits().catch(e => {
  console.error(e);
  process.exit(1);
});
