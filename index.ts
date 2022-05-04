import express, { Request, Response } from "express";
import dotenv from "dotenv";
import path from "path";
import cors from "cors";
import { PrismaClient } from "@prisma/client";
import dayjs from "dayjs";
import { query, validationResult } from "express-validator";
import * as jose from "jose";

// -------------------------------------------------

dotenv.config();
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

const corsMiddleware = cors(corsOptions);

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
app.get("/info", corsMiddleware, async (req: Request, res: Response) => {
  const { threadId } = req.query;
  // TODO: type
  if (threadId) {
    const tracker = await prisma.tracker.findFirst({
      where: { threadId: String(threadId) },
      include: { views: true },
    });
    if (!tracker) {
      res.status(400).send(JSON.stringify({}));
      return;
    }

    const views = tracker.views;

    res.send(JSON.stringify({ views }));
  } else {
    res.status(400).send(JSON.stringify({}));
  }
});

app.get("/dashboard", async (req: Request, res: Response) => {
  const views = await prisma.view.findMany();
  const trackers = await prisma.tracker.findMany();

  console.log("views", views);
  console.log("trackers", trackers);

  res.send(JSON.stringify({ views, trackers }));
});

app.options("/report", corsMiddleware);
app.post("/report", corsMiddleware, async (req: Request, res: Response) => {
  const { trackId } = req.body;
  const userId = 1;
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
});

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
    console.log(`https://${req.hostname}/magic?token=${magicLinkToken.token}`);

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

    const accessToken = await new jose.SignJWT({})
      .setProtectedHeader({ alg: "HS256" })
      .setIssuedAt()
      .setSubject(subject)
      .setExpirationTime(`${ACCESS_TOKEN_EXPIRES_HOURS}h`)
      .sign(new TextEncoder().encode("asdf"));

    return res.redirect(`/login#accessToken=${accessToken}&expiresIn=${ACCESS_TOKEN_EXPIRES_HOURS * 60 * 60}`);
  }
);

// -------------------------------------------------

if (!process.env.PORT) {
  throw new Error("Missing PORT");
}
const port = parseInt(process.env.PORT, 10);

app.listen(port, async () => {
  console.log(`[server]: Server is running on ${port}`);
});
