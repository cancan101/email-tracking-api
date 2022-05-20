/*
  Warnings:

  - The primary key for the `MagicLinkToken` table will be changed. If it partially fails, the table could be left without primary key constraint.
  - The primary key for the `Tracker` table will be changed. If it partially fails, the table could be left without primary key constraint.
  - The primary key for the `View` table will be changed. If it partially fails, the table could be left without primary key constraint.
  - Changed the type of `id` on the `MagicLinkToken` table. No cast exists, the column would be dropped and recreated, which cannot be done if there is data, since the column is required.
  - Changed the type of `id` on the `Tracker` table. No cast exists, the column would be dropped and recreated, which cannot be done if there is data, since the column is required.
  - Changed the type of `id` on the `View` table. No cast exists, the column would be dropped and recreated, which cannot be done if there is data, since the column is required.

*/
-- AlterTable
ALTER TABLE "MagicLinkToken" ALTER COLUMN "id" SET DATA TYPE UUID USING LPAD(TO_HEX("id"::int), 32, '0')::UUID;

-- AlterTable
ALTER TABLE "Tracker" ALTER COLUMN "id" SET DATA TYPE UUID USING LPAD(TO_HEX("id"::int), 32, '0')::UUID;

-- AlterTable
ALTER TABLE "View" ALTER COLUMN "id" SET DATA TYPE UUID USING LPAD(TO_HEX("id"::int), 32, '0')::UUID;
