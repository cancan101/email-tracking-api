import dotenv from "dotenv";
import {
  cleanEnv,
  str,
  email,
  port,
  num,
  url,
  host,
  bool,
  makeValidator,
} from "envalid";

// -------------------------------------------------

dotenv.config();

// Reject short secrets at boot so a misconfigured deploy fails fast instead
// of running with cryptographically weak HS256 / cookie-signing keys. 32 chars
// is the minimum to give HMAC-SHA256 a full block of entropy.
const SECRET_MIN_LENGTH = 32;
const secret = makeValidator<string>((value) => {
  if (typeof value !== "string" || value.length < SECRET_MIN_LENGTH) {
    throw new Error(
      `expected at least ${SECRET_MIN_LENGTH} characters, got ${typeof value === "string" ? value.length : typeof value}`,
    );
  }
  return value;
});

const env = cleanEnv(process.env, {
  JWT_ACCESS_TOKEN_SECRET: secret(),
  COOKIE_SESSION_SECRET: secret(),
  COOKIE_SESSION_SECURE: bool({ default: true, devDefault: false }),
  SMTP2GO_API_KEY: str(),
  PORT: port(),
  // Use the email address or domain you verified
  MAGIC_LINK_FROM_EMAIL: email(),
  MAGIC_LINK_FROM_NAME: str({ default: undefined }),
  ACCESS_TOKEN_EXPIRES_HOURS: num({ default: 2 }),
  MAGIC_TOKEN_EXPIRES_HOURS: num({ default: 24 }),
  SENTRY_TRACES_SAMPLE_RATE: num({ default: 0.05 }),
  TRUST_PROXY_NUM: num({ default: undefined }),
  GMAIL_ADDON_REDIRECT_URI: url(),
  GMAIL_ADDON_CLIENT_ID: str({ devDefault: "CLIENT_ID" }),
  GMAIL_ADDON_CLIENT_SECRET: str({ devDefault: "CLIENT_SECRET" }),
  SENTRY_PROJECT_ID_EXTENSION: str(),
  SENTRY_HOST_EXTENSION: host(),
  SELF_VIEW_THRESHOLD_SEC: num({ default: 10 }),
  WEB_CONCURRENCY: num({ default: 1, devDefault: 0 }),
  SENTRY_TUNNEL_SIZE_LIMIT: str({ default: "100kb" }),
});

export default env;
