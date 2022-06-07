/*
  Warnings:

  - You are about to drop the column `threadid` on the `Tracker` table. All the data in the column will be lost.
  - Added the required column `threadId` to the `Tracker` table without a default value. This is not possible if the table is not empty.

*/
-- AlterTable
ALTER TABLE "Tracker" DROP COLUMN "threadid",
ADD COLUMN     "threadId" TEXT NOT NULL;
