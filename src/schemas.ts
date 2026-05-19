import { z } from "zod";

const UUID = z.string().uuid();

// userId can be a historical value (e.g. inserted manually via the
// add_user script) that doesn't satisfy RFC 4122 version/variant bits but
// is otherwise a valid 8-4-4-4-12 hex string. express-validator's old
// isUUID() accepted these; zod's .uuid() does not. Use a regex for userId
// only — every other UUID field in this app is minted by Prisma's
// @default(uuid()) or randomUUID(), so strict RFC checks are correct there.
const USER_ID_REGEX =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const userIdSchema = z
  .string()
  .regex(USER_ID_REGEX, { message: "Invalid UUID format" });

// Subject and body fields are bounded so a client cannot post arbitrarily
// large strings into the DB. 1000 chars is comfortably above any real
// Gmail thread / subject length while keeping a sane upper bound.
const BOUNDED_STRING_MAX = 1000;
const boundedString = z.string().min(1).max(BOUNDED_STRING_MAX);

export const imageQuerySchema = z.object({
  trackId: UUID,
});

export const imageParamsSchema = z.object({
  trackingSlug: UUID,
  trackId: UUID,
});

export const threadParamsSchema = z.object({
  threadId: boundedString,
});

export const viewsQuerySchema = z.object({
  userId: userIdSchema,
  // Express delivers query values as strings; coerce + validate.
  limit: z.coerce.number().int().positive().optional(),
});

export const trackerBodySchema = z.object({
  trackId: UUID,
  threadId: boundedString,
  emailId: boundedString,
  emailSubject: boundedString,
  // Accept either a numeric millisecond timestamp or its stringified form.
  scheduledTimestamp: z
    .union([z.number().int().positive(), z.string().regex(/^\d+$/)])
    .optional(),
  selfLoadMitigation: z.boolean().optional(),
});

export const magicLoginQuerySchema = z.object({
  token: UUID,
});

export const requestMagicBodySchema = z.object({
  email: z.string().email(),
});

export const useMagicBodySchema = z.object({
  token: UUID,
});

export const oauthAuthQuerySchema = z
  .object({
    login_hint: z.string().email(),
  })
  .passthrough(); // oauth lib reads its own query params; preserve them
