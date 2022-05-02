-- CreateTable
CREATE TABLE "Tracker" (
    "id" SERIAL NOT NULL,
    "trackId" UUID NOT NULL,
    "emailId" TEXT NOT NULL,
    "threadid" TEXT NOT NULL,

    CONSTRAINT "Tracker_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "View" (
    "id" SERIAL NOT NULL,
    "trackerId" INTEGER NOT NULL,
    "clientIp" TEXT NOT NULL,
    "userAgent" TEXT NOT NULL,

    CONSTRAINT "View_pkey" PRIMARY KEY ("id")
);

-- AddForeignKey
ALTER TABLE "View" ADD CONSTRAINT "View_trackerId_fkey" FOREIGN KEY ("trackerId") REFERENCES "Tracker"("id") ON DELETE RESTRICT ON UPDATE CASCADE;
