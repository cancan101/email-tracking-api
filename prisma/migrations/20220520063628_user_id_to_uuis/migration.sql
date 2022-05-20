/*
  Warnings:

  - Changed the type of `userId` on the `MagicLinkToken` table. No cast exists, the column would be dropped and recreated, which cannot be done if there is data, since the column is required.
  - Changed the type of `userId` on the `Tracker` table. No cast exists, the column would be dropped and recreated, which cannot be done if there is data, since the column is required.

*/
-- AlterTable
ALTER TABLE "MagicLinkToken" ALTER COLUMN "userId" SET DATA TYPE UUID USING LPAD(TO_HEX("userId"::int), 32, '0')::UUID;

-- AlterTable
ALTER TABLE "Tracker" ALTER COLUMN "userId"  SET DATA TYPE UUID USING LPAD(TO_HEX("userId"::int), 32, '0')::UUID;
