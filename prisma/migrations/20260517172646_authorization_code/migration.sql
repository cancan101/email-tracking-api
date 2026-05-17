-- CreateTable
CREATE TABLE "AuthorizationCode" (
    "code" VARCHAR NOT NULL,
    "clientId" VARCHAR NOT NULL,
    "userId" UUID NOT NULL,
    "redirectUri" VARCHAR NOT NULL,
    "scope" VARCHAR,
    "expiresAt" TIMESTAMPTZ(6) NOT NULL,
    "createdAt" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "consumedAt" TIMESTAMPTZ(6),

    CONSTRAINT "AuthorizationCode_pkey" PRIMARY KEY ("code")
);

-- CreateIndex
CREATE INDEX "AuthorizationCode_expiresAt_idx" ON "AuthorizationCode"("expiresAt");
