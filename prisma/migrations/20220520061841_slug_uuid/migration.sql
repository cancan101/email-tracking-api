/*
  Warnings:

  - Changed the type of `slug` on the `User` table. No cast exists, the column would be dropped and recreated, which cannot be done if there is data, since the column is required.

*/
-- AlterTable
ALTER TABLE "User" ALTER COLUMN "slug" SET DATA TYPE UUID USING slug::uuid;
