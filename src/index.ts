import throng from "throng";

import env from "./settings";
import { app } from "./app";

function start() {
  app.listen(env.PORT, async () => {
    console.log(`[server]: Server is running on ${env.PORT}`);
  });
}

if (env.WEB_CONCURRENCY === 0) {
  start();
} else {
  console.log("Using throng");
  throng({
    workers: env.WEB_CONCURRENCY,
    lifetime: Infinity,
    start,
  });
}
