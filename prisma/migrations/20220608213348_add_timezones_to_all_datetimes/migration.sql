-- AlterTable
ALTER TABLE "MagicLinkToken" ALTER COLUMN "createdAt" SET DATA TYPE TIMESTAMPTZ,
ALTER COLUMN "expiresAt" SET DATA TYPE TIMESTAMPTZ,
ALTER COLUMN "usedAt" SET DATA TYPE TIMESTAMPTZ;

-- AlterTable
ALTER TABLE "Tracker" ALTER COLUMN "createdAt" SET DATA TYPE TIMESTAMPTZ;

-- AlterTable
ALTER TABLE "View" ALTER COLUMN "createdAt" SET DATA TYPE TIMESTAMPTZ;
