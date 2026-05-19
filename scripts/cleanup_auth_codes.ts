import { PrismaClient } from "@prisma/client";
const { program } = require("commander");

// One-shot cleanup of the AuthorizationCode table. Designed to be invoked
// from Heroku Scheduler (or any cron) once a day:
//
//   npm run cleanup:auth-codes
//
// Deletes rows whose expiresAt is older than a grace period (default 1 day).
// Keeping recently-expired rows around briefly is useful for forensic logs
// if a replayed code is reported.

const prisma = new PrismaClient();

async function cleanupAuthCodes(graceHours: number): Promise<number> {
  const cutoff = new Date(Date.now() - graceHours * 60 * 60 * 1000);
  const result = await prisma.authorizationCode.deleteMany({
    where: { expiresAt: { lt: cutoff } },
  });
  return result.count;
}

program
  .option(
    "--grace-hours <hours>",
    "delete codes whose expiresAt is older than now minus this many hours",
    "24",
  )
  .action(async (opts: { graceHours: string }) => {
    const graceHours = parseInt(opts.graceHours, 10);
    if (isNaN(graceHours) || graceHours < 0) {
      console.error(`Invalid --grace-hours: ${opts.graceHours}`);
      process.exit(2);
    }
    try {
      const deleted = await cleanupAuthCodes(graceHours);
      console.log(
        JSON.stringify({
          event: "cleanup_auth_codes",
          deleted,
          graceHours,
        }),
      );
    } catch (err) {
      console.error(err);
      process.exit(1);
    } finally {
      await prisma.$disconnect();
    }
  });

// Only parse argv when invoked as a CLI; tests import this module and would
// otherwise see the jest argv ("-i", etc.) and bail.
if (require.main === module) {
  program.parse();
}

export { cleanupAuthCodes };
