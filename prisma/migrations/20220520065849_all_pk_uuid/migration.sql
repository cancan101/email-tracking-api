/*
  Warnings:

  - The primary key for the `MagicLinkToken` table will be changed. If it partially fails, the table could be left without primary key constraint.
  - The primary key for the `Tracker` table will be changed. If it partially fails, the table could be left without primary key constraint.
  - The primary key for the `View` table will be changed. If it partially fails, the table could be left without primary key constraint.

*/
-- AlterTable
ALTER TABLE "MagicLinkToken" ALTER COLUMN "id" SET DATA TYPE TEXT;

-- AlterTable
ALTER TABLE "Tracker"  ALTER COLUMN "id" SET DATA TYPE TEXT;

-- AlterTable
ALTER TABLE "View"  ALTER COLUMN "id" SET DATA TYPE TEXT;
