/*
  Warnings:

  - A unique constraint covering the columns `[emailId]` on the table `Tracker` will be added. If there are existing duplicate values, this will fail.

*/
-- CreateIndex
CREATE UNIQUE INDEX "Tracker_emailId_key" ON "Tracker"("emailId");
