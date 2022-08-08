import env from "./settings";
import { app } from "./app";

app.listen(env.PORT, async () => {
  console.log(`[server]: Server is running on ${env.PORT}`);
});
