-- AlterTable
ALTER TABLE "Tracker" ALTER COLUMN "emailId" SET DATA TYPE VARCHAR,
ALTER COLUMN "threadId" SET DATA TYPE VARCHAR,
ALTER COLUMN "emailSubject" SET DATA TYPE VARCHAR;

-- AlterTable
ALTER TABLE "User" ALTER COLUMN "email" SET DATA TYPE VARCHAR;

-- AlterTable
ALTER TABLE "View" ALTER COLUMN "clientIp" SET DATA TYPE VARCHAR;