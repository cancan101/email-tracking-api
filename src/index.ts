import throng from "throng";

import env from "./settings";
import { app } from "./app";
import logger from "./logger";

function start() {
  app.listen(env.PORT, async () => {
    logger.info({ port: env.PORT }, "Server listening");
  });
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
