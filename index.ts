import express, { Request, Response, NextFunction } from "express";
import dotenv from "dotenv";
import path from "path";
import cors from "cors";
import { PrismaClient, Prisma, View } from "@prisma/client";
import dayjs from "dayjs";
import {
  query,
  validationResult,
  body,
  matchedData,
  param,
} from "express-validator";
import jsonwebtoken from "jsonwebtoken";
import { expressjwt, ExpressJwtRequestUnrequired } from "express-jwt";
import sgMail from "@sendgrid/mail";
import { cleanEnv, str, email, port } from "envalid";
import fs from "fs";

// -------------------------------------------------

dotenv.config();

const env = cleanEnv(process.env, {
  JWT_ACCESS_TOKEN_SECRET: str(),
  SENDGRID_API_KEY: str(),
  PORT: port(),
  MAGIC_LINK_FROM_EMAIL: email(),
});

// -------------------------------------------------

sgMail.setApiKey(env.SENDGRID_API_KEY);

// -------------------------------------------------

// we assume that this is the file run in this location relative to responses directory
const transparentGifPath = path.join(
  __dirname,
  "./responses",
  "transparent.gif"
);
if (!fs.existsSync(transparentGifPath)) {
  throw Error(`No such file: ${transparentGifPath}`);
}

// -------------------------------------------------

const MAGIC_TOKEN_EXPIRES: number = 7;
const ACCESS_TOKEN_EXPIRES_HOURS: number = 2;

const GMAIL_ORIGIN: string = "https://mail.google.com";

const JWT_ALGORITHM = "HS256";

// -------------------------------------------------

const prisma = new PrismaClient();
const app = express();

// -------------------------------------------------

app.use(express.json());

// This is ok on Heroku:
app.set("trust proxy", ["uniquelocal"]);

const corsOptions = {
  origin: [GMAIL_ORIGIN],
};

const corsMiddleware = cors(corsOptions);
const jwtMiddlware = expressjwt({
  secret: env.JWT_ACCESS_TOKEN_SECRET,
  algorithms: [JWT_ALGORITHM],
});

const UseJwt = [
  jwtMiddlware,
  function (err: any, req: Request, res: Response, next: NextFunction) {
    // make sure to respond with JSON in case of 401 from JWT library
    if (err.name === "UnauthorizedError") {
      res.status(err.status ?? 401).json(err);
    } else {
      next(err);
    }
  },
];

// -------------------------------------------------

async function fetchWithTimeout(
  resource: RequestInfo,
  options: RequestInit & { timeout?: number } = {}
) {
  const { timeout = 8000 } = options;

  const controller = new AbortController();
  const id = setTimeout(() => controller.abort(), timeout);
  const response = await fetch(resource, {
    ...options,
    signal: controller.signal,
  });
  clearTimeout(id);
  return response;
}

type ClientIpGeo = {
  source: string;
  data?: object;
  rule?: string;
};

async function processImage(
  trackId: string,
  req: Request,
  res: Response
): Promise<void> {
  const clientIp = req.ip;
  const userAgent = req.headers["user-agent"];

  let clientIpGeo: ClientIpGeo | null = null;

  const isProxied =
    userAgent !== undefined &&
    (userAgent.includes("YahooMailProxy") ||
      userAgent.includes("GoogleImageProxy"));

  if (userAgent === undefined || !isProxied) {
    try {
      const resp = await fetchWithTimeout(`http://ipwho.is/${clientIp}`);
      clientIpGeo = { source: "ipwhois" };
      if (resp.ok) {
        const clientIpGeoData = await resp.json();
        const isGoogleLlc = clientIpGeoData?.connection?.isp === "Google LLC";
        if (isGoogleLlc) {
          clientIpGeo.rule = "connectionIspGoogleLlc";
        } else {
          clientIpGeo.data = clientIpGeoData;
        }
      }
    } catch {}
  }

  try {
    await prisma.view.create({
      data: {
        trackId,
        clientIp,
        clientIpGeo: clientIpGeo ?? undefined,
        userAgent: userAgent ?? "",
      },
    });
  } catch (error) {
    // ask forgiveness
    if (error instanceof Prisma.PrismaClientKnownRequestError) {
      if (error.code === "P2003") {
        console.log("Unknown tracker requested", trackId);
      } else {
        console.error(error);
      }
    } else {
      console.error(error);
    }
  }
  return;
}

// Deprecated
app.get(
  "/image.gif",
  query("trackId").isString().isUUID(),
  async (req: Request, res: Response): Promise<void> => {
    res.sendFile(transparentGifPath);

    // Finds the validation errors in this request and wraps them in an object with handy functions
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      // Just send the image in this case
      return;
    }
    const data = matchedData(req);
    const trackId = data.trackId as string;

    await processImage(trackId, req, res);
  }
);

app.get(
  "/t/:trackingSlug/:trackId/image.gif",
  param("trackingSlug").isString().isUUID(),
  param("trackId").isString().isUUID(),
  async (req: Request, res: Response): Promise<void> => {
    res.sendFile(transparentGifPath);

    // Finds the validation errors in this request and wraps them in an object with handy functions
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      // Just send the image in this case
      return;
    }
    const data = matchedData(req);
    const trackId = data.trackId as string;

    await processImage(trackId, req, res);
  }
);

const getViewsForTracker = async (threadId: string): Promise<null | View[]> => {
  const trackers = await prisma.tracker.findMany({
    where: { threadId },
    include: { views: true },
    orderBy: { createdAt: "desc" },
  });

  if (trackers.length === 0) {
    return null;
  }

  const views = trackers
    .flatMap((tracker) => tracker.views)
    // since we are not getting this from db due to flatmap
    .sort((a, b) => -(a.createdAt.getTime() - b.createdAt.getTime()));

  return views;
};

app.options("/info", corsMiddleware);
app.get(
  "/info",
  corsMiddleware,
  ...UseJwt,
  query("threadId").isString(),
  async (req: Request, res: Response): Promise<void> => {
    // Finds the validation errors in this request and wraps them in an object with handy functions
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      res.status(400).json({ errors: errors.array() });
      return;
    }
    const data = matchedData(req);
    const threadId = String(data.threadId);

    const views = await getViewsForTracker(threadId);

    if (views === null) {
      res.send(JSON.stringify({ views: null, error_code: "unknown_tracker" }));
      return;
    }

    res.send(JSON.stringify({ views }));
    return;
  }
);

app.options("/dashboard", corsMiddleware);
app.get(
  "/dashboard",
  corsMiddleware,
  ...UseJwt,
  query("userId").isUUID(),
  async (req: Request, res: Response): Promise<void> => {
    // Finds the validation errors in this request and wraps them in an object with handy functions
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      res.status(400).json({ errors: errors.array() });
      return;
    }
    const data = matchedData(req);
    const userId = data.userId as string;

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
  body("trackId").isString().isUUID(),
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
      return;
    }
    const data = matchedData(req);
    const { trackId, threadId, emailId, emailSubject } = data;
    if (trackId) {
      const userId = req.auth.sub;
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

app.get("/logged-in", (req: Request, res: Response): void => {
  res.status(200).send("You are logged in. You may close this window.");
  return;
});

app.options("/login/magic", corsMiddleware);
app.post(
  "/login/magic",
  corsMiddleware,
  body("email").isString().isEmail({ domain_specific_validation: true }),
  async (req: Request, res: Response): Promise<void> => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      res.status(400).json({ errors: errors.array() });
      return;
    }

    const protocol = req.protocol;
    // req.get("Host") to include the port as req.hostname did not work
    const host = req.get("Host");

    // From here on out, just return 200
    res.status(200).send(JSON.stringify({}));

    const data = matchedData(req);

    const { email } = data;

    // Consider wrapping this all in try / catch
    const user = await prisma.user.findFirst({ where: { email } });
    if (!user) {
      return;
    }

    const magicLinkToken = await prisma.magicLinkToken.create({
      data: {
        userId: user.id,
        expiresAt: dayjs().add(MAGIC_TOKEN_EXPIRES, "day").toDate(),
      },
    });

    const loginUrl = `${protocol}://${host}/magic?token=${magicLinkToken.token}`;

    const msg = {
      to: user.email,
      from: env.MAGIC_LINK_FROM_EMAIL, // Use the email address or domain you verified
      subject: "Email Tracker",
      text: `Login using: ${loginUrl}`,
      // Don't mangle the URL with tracking:
      tracking_settings: { click_tracking: { enable: false } },
    };

    console.log("loginUrl:", email, loginUrl);

    try {
      // TODO(cancan101): option to mock this (merge with log above)
      await sgMail.send(msg);
    } catch (error: any) {
      console.error(error);

      if (error.response) {
        console.error(error.response.body);
      }
    }

    return;
  }
);

// TODO(cancan): make this a POST that returns this information.
// The GET should just be an empty page
app.get(
  "/magic",
  query("token").isString().isUUID(),
  async (req: Request, res: Response): Promise<void> => {
    // Finds the validation errors in this request and wraps them in an object with handy functions
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      res.status(400).json({ errors: errors.array() });
      return;
    }

    const token = req.query.token as string;

    const magicLinkToken = await prisma.magicLinkToken.findFirst({
      where: { token },
      include: { user: { select: { email: true, slug: true } } },
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
    const { email, slug } = magicLinkToken.user;

    const expiresIn = ACCESS_TOKEN_EXPIRES_HOURS * 60 * 60;

    const accessToken = await jsonwebtoken.sign(
      {},
      env.JWT_ACCESS_TOKEN_SECRET,
      {
        algorithm: JWT_ALGORITHM,
        expiresIn,
        subject,
      }
    );

    res.redirect(
      `/login#accessToken=${accessToken}&expiresIn=${expiresIn}&emailAccount=${email}&trackingSlug=${slug}`
    );
    return;
  }
);

// Probably not needed long term
app.get("/ping", (req: Request, res: Response): void => {
  res.status(200).send("");
});

// -------------------------------------------------

app.listen(env.PORT, async () => {
  console.log(`[server]: Server is running on ${env.PORT}`);
});
