import express, { Request, Response, NextFunction } from "express";
import dotenv from "dotenv";
import path from "path";
import cors from "cors";
import { PrismaClient } from "@prisma/client";
import dayjs from "dayjs";
import { query, validationResult } from "express-validator";
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

app.get("/ping", (req: Request, res: Response) => {
  res.status(200).send("");
});

app.get("/image.gif", async (req: Request, res: Response) => {
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
  } else {
    res.status(400).send();
  }
});

app.options("/info", corsMiddleware);
app.get(
  "/info",
  corsMiddleware,
  ...UseJwt,
  async (req: Request, res: Response) => {
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
    } else {
      res.status(400).send(JSON.stringify({ error_code: "missing_thread_id" }));
    }
  }
);

app.options("/dashboard", corsMiddleware);
app.get(
  "/dashboard",
  corsMiddleware,
  ...UseJwt,
  query("userId").isInt(),
  async (req: Request, res: Response) => {
    // Finds the validation errors in this request and wraps them in an object with handy functions
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }
    const userIdStr = req.query.userId as string;
    const userId = parseInt(userIdStr, 10);

    const views = await prisma.view.findMany({
      where: { tracker: { userId } },
      orderBy: { createdAt: "desc" },
      include: { tracker: { select: { threadId: true } } },
    });
    const trackers = await prisma.tracker.findMany({ where: { userId } });

    console.log("views", views);
    console.log("trackers", trackers);

    res.send(JSON.stringify({ views, trackers }));
  }
);

app.options("/report", corsMiddleware);
app.post(
  "/report",
  corsMiddleware,
  ...UseJwt,
  async (req: ExpressJwtRequestUnrequired, res: Response) => {
    if (!req.auth || !req.auth.sub) {
      res.status(401).send(JSON.stringify({}));
      return;
    }
    const { trackId } = req.body;
    const userId = parseInt(req.auth.sub, 10);
    if (trackId) {
      await prisma.tracker.create({
        data: {
          userId,
          trackId,
          threadId: req.body.threadId,
          emailId: req.body.emailId,
        },
      });
      res.send(JSON.stringify({}));
    } else {
      res.status(400).send(JSON.stringify({}));
    }
  }
);

app.get("/login", async (req: Request, res: Response) => {
  res.send("Logging in...");
});

app.get("/logged-in", async (req: Request, res: Response) => {
  res.send("You are logged in. You may close this window.");
});

app.options("/login/magic", corsMiddleware);
app.post(
  "/login/magic",
  corsMiddleware,
  async (req: Request, res: Response) => {
    const { email } = req.body;
    if (!email) {
      res.status(400).send(JSON.stringify({ error: "missing_email" }));
      return;
    }
    const user = await prisma.user.findFirst({ where: { email } });
    if (!user) {
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

    res.send(JSON.stringify({}));
  }
);

app.get(
  "/magic",
  query("token").isUUID().isString(),
  async (req: Request, res: Response) => {
    // Finds the validation errors in this request and wraps them in an object with handy functions
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const token = req.query.token as string;

    const magicLinkToken = await prisma.magicLinkToken.findFirst({
      where: { token: String(token) },
    });

    if (!magicLinkToken) {
      return res.status(400).json({ error_code: "token_invalid" });
    } else if (magicLinkToken.usedAt) {
      return res.status(400).json({ error_code: "token_used" });
    } else if (magicLinkToken.expiresAt < dayjs().toDate()) {
      return res.status(400).json({ error_code: "token_used" });
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

    return res.redirect(
      `/login#accessToken=${accessToken}&expiresIn=${expiresIn}`
    );
  }
);

// -------------------------------------------------

app.listen(PORT, async () => {
  console.log(`[server]: Server is running on ${PORT}`);
});
