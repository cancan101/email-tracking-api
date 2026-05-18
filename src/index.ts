import throng from "throng";

import env from "./settings";
import { app } from "./app";
import logger from "./logger";
import prisma from "./client";

// Heroku sends SIGTERM and waits up to 30s for the process to exit. Without
// a handler, in-flight requests are dropped at deploy time. Close the HTTP
// server (stops accepting new connections, waits for active ones to finish)
// and disconnect Prisma so its pool drains cleanly.
const SHUTDOWN_TIMEOUT_MS = 25_000;

function start() {
  const server = app.listen(env.PORT, async () => {
    logger.info({ port: env.PORT }, "Server listening");
  });

  let shuttingDown = false;
  const shutdown = (signal: string) => {
    if (shuttingDown) return;
    shuttingDown = true;
    logger.info({ signal }, "Shutdown signal received");

    // Hard exit if cleanup takes too long so we never block past the
    // platform's kill window.
    const killTimer = setTimeout(() => {
      logger.error("Shutdown timed out; exiting forcefully");
      process.exit(1);
    }, SHUTDOWN_TIMEOUT_MS);
    killTimer.unref();

    server.close((err) => {
      if (err) {
        logger.error({ err }, "Error closing HTTP server");
      }
      prisma
        .$disconnect()
        .catch((dErr) =>
          logger.error({ err: dErr }, "Error disconnecting Prisma"),
        )
        .finally(() => {
          logger.info("Shutdown complete");
          process.exit(err ? 1 : 0);
        });
    });
  };

  process.on("SIGTERM", () => shutdown("SIGTERM"));
  process.on("SIGINT", () => shutdown("SIGINT"));
}

logger.info({ webConcurrency: env.WEB_CONCURRENCY }, "Boot");
if (env.WEB_CONCURRENCY === 0) {
  start();
} else {
  logger.info("Using throng");
  throng({
    workers: env.WEB_CONCURRENCY,
    lifetime: Infinity,
    start,
  });
}
