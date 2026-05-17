import { z } from "zod";

const UUID = z.string().uuid();

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
  userId: UUID,
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
