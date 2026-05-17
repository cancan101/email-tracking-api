import pino from "pino";

const logger = pino({
  level: process.env.LOG_LEVEL ?? "info",
  // Redact common credential / PII fields if they're ever attached to a log
  // call by accident.
  redact: {
    paths: [
      "req.headers.authorization",
      "req.headers.cookie",
      "*.password",
      "*.token",
    ],
    censor: "[redacted]",
  },
});

export default logger;
