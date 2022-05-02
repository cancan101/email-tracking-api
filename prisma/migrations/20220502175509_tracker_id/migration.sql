/*
  Warnings:

  - You are about to drop the column `trackerId` on the `View` table. All the data in the column will be lost.
  - A unique constraint covering the columns `[trackId]` on the table `Tracker` will be added. If there are existing duplicate values, this will fail.
  - Added the required column `trackId` to the `View` table without a default value. This is not possible if the table is not empty.

*/
-- DropForeignKey
ALTER TABLE "View" DROP CONSTRAINT "View_trackerId_fkey";

-- AlterTable
ALTER TABLE "View" DROP COLUMN "trackerId",
ADD COLUMN     "trackId" UUID NOT NULL;

-- CreateIndex
CREATE UNIQUE INDEX "Tracker_trackId_key" ON "Tracker"("trackId");

-- AddForeignKey
ALTER TABLE "View" ADD CONSTRAINT "View_trackId_fkey" FOREIGN KEY ("trackId") REFERENCES "Tracker"("trackId") ON DELETE RESTRICT ON UPDATE CASCADE;
