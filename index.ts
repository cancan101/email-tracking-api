import express, { Request, Response, NextFunction } from "express";
import dotenv from "dotenv";
import path from "path";
import cors from "cors";
import { PrismaClient } from "@prisma/client";
import dayjs from "dayjs";
import { query, validationResult, body, matchedData } from "express-validator";
import jsonwebtoken from "jsonwebtoken";
import { expressjwt, ExpressJwtRequestUnrequired } from "express-jwt";

// -------------------------------------------------

dotenv.config();

const { JWT_ACCESS_TOKEN_SECRET, PORT: PORT_STR } = process.env;

if (!PORT_STR) {
  throw new Error("Missing PORT");
}
const PORT = parseInt(PORT_STR, 10);

if (!JWT_ACCESS_TOKEN_SECRET) {
  throw new Error("Missing JWT_ACCESS_TOKEN_SECRET");
}

// -------------------------------------------------

const MAGIC_TOKEN_EXPIRES: number = 7;
const ACCESS_TOKEN_EXPIRES_HOURS: number = 2;

// -------------------------------------------------

const prisma = new PrismaClient();
const app = express();

// -------------------------------------------------

app.use(express.json());

// This is ok on Heroku:
app.set("trust proxy", ["uniquelocal"]);

const corsOptions = {
  origin: ["https://mail.google.com"],
};

const JWT_ALGORITHM = "HS256";
const corsMiddleware = cors(corsOptions);
const jwtMiddlware = expressjwt({
  secret: JWT_ACCESS_TOKEN_SECRET,
  algorithms: [JWT_ALGORITHM],
});

const UseJwt = [
  jwtMiddlware,
  function (err: any, req: Request, res: Response, next: NextFunction) {
    if (err.name === "UnauthorizedError") {
      res.status(err.status ?? 401).json(err);
    } else {
      next(err);
    }
  },
];

// -------------------------------------------------

app.get("/ping", (req: Request, res: Response): void => {
  res.status(200).send("");
});

app.get("/image.gif", async (req: Request, res: Response): Promise<void> => {
  const { trackId } = req.query;

  // TODO: handle the trackId of other types
  if (trackId) {
    await prisma.view.create({
      data: {
        trackId: String(trackId),
        clientIp: req.ip,
        userAgent: req.headers["user-agent"] ?? "",
      },
    });
    res.sendFile(path.join(__dirname, "../responses", "transparent.gif"));
    return;
  } else {
    res.status(400).send();
    return;
  }
});

app.options("/info", corsMiddleware);
app.get(
  "/info",
  corsMiddleware,
  ...UseJwt,
  async (req: Request, res: Response): Promise<void> => {
    const { threadId } = req.query;
    // TODO: type
    if (threadId) {
      const trackers = await prisma.tracker.findMany({
        where: { threadId: String(threadId) },
        include: { views: true },
      });

      if (trackers.length === 0) {
        res.status(400).send(JSON.stringify({ error_code: "unknown_tracker" }));
        return;
      }

      const views = trackers.flatMap((tracker) => tracker.views);

      res.send(JSON.stringify({ views }));
      return;
    } else {
      res.status(400).send(JSON.stringify({ error_code: "missing_thread_id" }));
      return;
    }
  }
);

app.options("/dashboard", corsMiddleware);
app.get(
  "/dashboard",
  corsMiddleware,
  ...UseJwt,
  query("userId").isInt(),
  async (req: Request, res: Response): Promise<void> => {
    // Finds the validation errors in this request and wraps them in an object with handy functions
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      res.status(400).json({ errors: errors.array() });
      return;
    }
    const data = matchedData(req);
    const userIdStr = data.userId as string;
    const userId = parseInt(userIdStr, 10);

    const views = await prisma.view.findMany({
      where: { tracker: { userId } },
      orderBy: { createdAt: "desc" },
      include: { tracker: { select: { threadId: true, emailSubject: true } } },
    });
    const trackers = await prisma.tracker.findMany({ where: { userId } });

    res.send(JSON.stringify({ views, trackers }));
    return;
  }
);

app.options("/report", corsMiddleware);
app.post(
  "/report",
  corsMiddleware,
  ...UseJwt,
  body("trackId").isUUID().isString(),
  body("threadId").isString(),
  body("emailId").isString(),
  body("emailSubject").isString(),
  async (req: ExpressJwtRequestUnrequired, res: Response): Promise<void> => {
    if (!req.auth || !req.auth.sub) {
      res.status(401).send(JSON.stringify({}));
      return;
    }

    // Finds the validation errors in this request and wraps them in an object with handy functions
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      res.status(400).json({ errors: errors.array() });
      return
    }
    const data = matchedData(req);
    const { trackId, threadId, emailId, emailSubject } = data;
    if (trackId) {
      const userId = parseInt(req.auth.sub, 10);
      await prisma.tracker.create({
        data: {
          userId,
          trackId,
          threadId,
          emailId,
          emailSubject,
        },
      });
      res.status(201).send(JSON.stringify({}));
      return;
    } else {
      res.status(400).send(JSON.stringify({}));
      return;
    }
  }
);

app.get("/login", (req: Request, res: Response): void => {
  res.status(200).send("Logging in...");
  return;
});

app.get("/logged-in", (req: Request, res: Response): void  => {
  res.status(200).send("You are logged in. You may close this window.");
  return;
});

app.options("/login/magic", corsMiddleware);
app.post(
  "/login/magic",
  corsMiddleware,
  async (req: Request, res: Response): Promise<void> => {
    const { email } = req.body;
    if (!email) {
      // use validation middleware
      res.status(400).send(JSON.stringify({ error: "missing_email" }));
      return;
    }
    const user = await prisma.user.findFirst({ where: { email } });
    if (!user) {
      // TODO(cancan101): don't leak info here
      res.status(400).send(JSON.stringify({ error: "unknown_user" }));
      return;
    }

    const magicLinkToken = await prisma.magicLinkToken.create({
      data: {
        userId: user.id,
        expiresAt: dayjs().add(MAGIC_TOKEN_EXPIRES, "day").toDate(),
      },
    });

    // TODO send email here
    // req.get("Host") to include the port as req.hostname did not work
    console.log(
      `${req.protocol}://${req.get("Host")}/magic?token=${magicLinkToken.token}`
    );

    res.status(200).send(JSON.stringify({}));
    return;
  }
);

app.get(
  "/magic",
  query("token").isUUID().isString(),
  async (req: Request, res: Response): Promise<void> => {
    // Finds the validation errors in this request and wraps them in an object with handy functions
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      res.status(400).json({ errors: errors.array() });
      return;
    }

    const token = req.query.token as string;

    const magicLinkToken = await prisma.magicLinkToken.findFirst({
      where: { token: String(token) },
    });

    if (!magicLinkToken) {
      res.status(400).json({ error_code: "token_invalid" });
      return;
    } else if (magicLinkToken.usedAt) {
      res.status(400).json({ error_code: "token_used" });
      return;
    } else if (magicLinkToken.expiresAt < dayjs().toDate()) {
      res.status(400).json({ error_code: "token_used" });
      return;
    }

    await prisma.magicLinkToken.update({
      where: { id: magicLinkToken.id },
      data: {
        usedAt: dayjs().toDate(),
      },
    });

    const userId = magicLinkToken.userId;
    const subject = String(userId);

    const expiresIn = ACCESS_TOKEN_EXPIRES_HOURS * 60 * 60;

    const accessToken = await jsonwebtoken.sign({}, JWT_ACCESS_TOKEN_SECRET, {
      algorithm: JWT_ALGORITHM,
      expiresIn,
      subject,
    });

    res.redirect(
      `/login#accessToken=${accessToken}&expiresIn=${expiresIn}`
    );
    return;
  }
);

// -------------------------------------------------

app.listen(PORT, async () => {
  console.log(`[server]: Server is running on ${PORT}`);
});
