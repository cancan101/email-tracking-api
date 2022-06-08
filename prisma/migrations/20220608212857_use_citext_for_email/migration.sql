CREATE EXTENSION IF NOT EXISTS citext;

/*
  Warnings:

  - Changed the type of `email` on the `User` table. No cast exists, the column would be dropped and recreated, which cannot be done if there is data, since the column is required.

*/
-- AlterTable
ALTER TABLE "User" ALTER COLUMN "email" SET DATA TYPE CITEXT;
