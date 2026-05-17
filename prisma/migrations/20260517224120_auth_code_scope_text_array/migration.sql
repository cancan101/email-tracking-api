-- @node-oauth/oauth2-server v5 exposes AuthorizationCode#scope as string[]
-- instead of string. Drop and re-add as TEXT[]; safe because no rows have
-- been written to this table yet.
ALTER TABLE "AuthorizationCode" DROP COLUMN "scope";
ALTER TABLE "AuthorizationCode" ADD COLUMN "scope" TEXT[];
