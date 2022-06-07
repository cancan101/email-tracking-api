-- DropForeignKey
ALTER TABLE "MagicLinkToken" DROP CONSTRAINT "MagicLinkToken_userId_fkey";

-- DropForeignKey
ALTER TABLE "Tracker" DROP CONSTRAINT "Tracker_userId_fkey";

-- AlterTable
ALTER TABLE "MagicLinkToken" ALTER COLUMN "userId" SET DATA TYPE TEXT;

-- AlterTable
ALTER TABLE "Tracker" ALTER COLUMN "userId" SET DATA TYPE TEXT;
