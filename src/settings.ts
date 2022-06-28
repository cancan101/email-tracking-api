import dotenv from "dotenv";
import { cleanEnv, str, email, port, num, url, host } from "envalid";

// -------------------------------------------------

dotenv.config();

const env = cleanEnv(process.env, {
  JWT_ACCESS_TOKEN_SECRET: str(),
  COOKIE_SESSION_SECRET: str(),
  SENDGRID_API_KEY: str(),
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
});

export default env;
