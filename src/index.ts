import express, { Request, Response, NextFunction } from "express";
import path from "path";
import cors, { CorsOptions } from "cors";
import { PrismaClient, Prisma, View, Tracker } from "@prisma/client";
import dayjs from "dayjs";
import {
  query,
  validationResult,
  body,
  matchedData,
  param,
} from "express-validator";
import jsonwebtoken from "jsonwebtoken";
import { expressjwt, Request as JWTRequest } from "express-jwt";
import sgMail from "@sendgrid/mail";
import fs from "fs";
import * as Sentry from "@sentry/node";
import * as Tracing from "@sentry/tracing";
import OAuthServer from "express-oauth-server";
import { AuthorizationCodeModel, AuthorizationCode, User } from "oauth2-server";
import cookieSession from "cookie-session";
import crypto from "crypto";
import sentryTunnelHandler from "./sentry-tunnel";

import env from "./settings";

// -------------------------------------------------

const app = express();
const prisma = new PrismaClient();

// -------------------------------------------------

Sentry.init({
  integrations: [
    // enable HTTP calls tracing
    new Sentry.Integrations.Http({ tracing: true }),
    // enable Express.js middleware tracing
    new Tracing.Integrations.Express({ app }),

    new Tracing.Integrations.Prisma({ client: prisma }),
  ],

  // Set tracesSampleRate to 1.0 to capture 100%
  // of transactions for performance monitoring.
  // We recommend adjusting this value in production
  tracesSampleRate: env.SENTRY_TRACES_SAMPLE_RATE,
});

// RequestHandler creates a separate execution context using domains, so that every
// transaction/span/breadcrumb is attached to its own Hub instance
app.use(Sentry.Handlers.requestHandler());
// TracingHandler creates a trace for every incoming request
app.use(Sentry.Handlers.tracingHandler());

// -------------------------------------------------

sgMail.setApiKey(env.SENDGRID_API_KEY);

// -------------------------------------------------

app.use(
  cookieSession({
    secret: env.COOKIE_SESSION_SECRET,

    // Cookie Options
    sameSite: "strict",
    secure: true,
    // We use the same expiration here so that the we don't get stale access token
    // See comments about hacks below with how / when we generate the access token
    maxAge: env.ACCESS_TOKEN_EXPIRES_HOURS * 60 * 60 * 1000,
  })
);

// -------------------------------------------------

// we assume that this is the file run in this location relative to responses directory
const transparentGifPath = path.join(
  __dirname,
  "../responses",
  "transparent.gif"
);
if (!fs.existsSync(transparentGifPath)) {
  throw Error(`No such file: ${transparentGifPath}`);
}

// -------------------------------------------------

const GMAIL_ORIGIN: string = "https://mail.google.com";

const JWT_ALGORITHM = "HS256";

// -------------------------------------------------

app.use(express.json());

// This is ok on Heroku:
const trust_proxy = env.TRUST_PROXY_NUM ?? ["uniquelocal"];
app.set("trust proxy", trust_proxy);

const CORS_MAX_AGE_SEC = 1 * 60 * 60;
const corsOptions: CorsOptions = {
  origin: [GMAIL_ORIGIN],
  maxAge: CORS_MAX_AGE_SEC,
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

type GeoData = {
  city: string;
  region: string;
  isMobile?: boolean;
};

type ClientIpGeo = {
  source: string;
  data?: GeoData;
  dataRaw?: object;
  rule?: string;
  secondary?: ClientIpGeo;
};

async function lookupIpwhois(clientIp: string): Promise<ClientIpGeo | null> {
  let clientIpGeo: ClientIpGeo | null = null;
  const resp = await fetchWithTimeout(`http://ipwho.is/${clientIp}`);
  clientIpGeo = { source: "ipwhois" };
  if (resp.ok) {
    const clientIpGeoData = await resp.json();

    clientIpGeo.dataRaw = clientIpGeoData;

    const isp = clientIpGeoData?.connection?.isp;

    const isGoogleLlc = isp === "Google LLC";
    // https://developer.apple.com/support/prepare-your-network-for-icloud-private-relay/
    const isCloudflareInc = isp === "Cloudflare, Inc.";

    if (isGoogleLlc) {
      clientIpGeo.rule = "connectionIspGoogleLlc";
    } else if (isCloudflareInc) {
      clientIpGeo.rule = "connectionIspCloudflareInc";
    } else {
      clientIpGeo.data = {
        city: clientIpGeoData.city,
        region: clientIpGeoData.region,
      };
    }
  } else {
    const respJson = await resp.json();
    Sentry.captureException(
      new Error(
        `Unable to fetch IP geo data ${resp.status}: ${JSON.stringify(
          respJson
        )}`
      )
    );
  }
  return clientIpGeo;
}

async function lookupIpApi(clientIp: string): Promise<ClientIpGeo | null> {
  let clientIpGeo: ClientIpGeo | null = null;
  const resp = await fetchWithTimeout(
    `http://ip-api.com/json/${clientIp}?fields=status,message,country,countryCode,region,regionName,city,district,zip,lat,lon,timezone,isp,org,as,asname,mobile,proxy,hosting`
  );
  clientIpGeo = { source: "ip-api" };
  if (resp.ok) {
    const clientIpGeoData = await resp.json();

    clientIpGeo.dataRaw = clientIpGeoData;

    const isp = clientIpGeoData?.isp;

    const isGoogleLlc = isp === "Google LLC";
    // https://developer.apple.com/support/prepare-your-network-for-icloud-private-relay/
    const isCloudflareInc = isp === "Cloudflare, Inc.";

    const org = clientIpGeoData?.org;
    const isICloudPrivateRelay = org === "iCloud Private Relay";

    if (isGoogleLlc) {
      clientIpGeo.rule = "connectionIspGoogleLlc";
    } else if (isCloudflareInc) {
      clientIpGeo.rule = "connectionIspCloudflareInc";
    } else if (isICloudPrivateRelay) {
      clientIpGeo.rule = "orgICloudPrivateRelay";
    } else {
      clientIpGeo.data = {
        city: clientIpGeoData.city as string,
        region: clientIpGeoData.region as string,
        isMobile: clientIpGeoData.mobile as boolean,
      };
    }
  } else {
    const respJson = await resp.json();
    Sentry.captureException(
      new Error(
        `Unable to fetch IP geo data ${resp.status}: ${JSON.stringify(
          respJson
        )}`
      )
    );
  }
  return clientIpGeo;
}

async function processImage(
  trackId: string,
  req: Request,
  res: Response
): Promise<void> {
  const clientIp = req.ip;
  const userAgent = req.headers["user-agent"];

  let clientIpGeo: ClientIpGeo | null = null;

  const isProxiedGoogle =
    userAgent !== undefined && userAgent.includes("GoogleImageProxy");

  const isProxiedYahoo =
    userAgent !== undefined && userAgent.includes("YahooMailProxy");

  const isProxiedFront =
    userAgent !== undefined && userAgent.includes("FrontApp.com ImageProxy");

  const isProxied = isProxiedGoogle || isProxiedYahoo || isProxiedFront;

  if (isProxied) {
    clientIpGeo = { source: "userAgent" };
  } else {
    try {
      clientIpGeo = await lookupIpwhois(clientIp);
      const clientIpGeoSecondary = await lookupIpApi(clientIp);
      if (clientIpGeo === null) {
        clientIpGeo = clientIpGeoSecondary;
      } else {
        clientIpGeo.secondary = clientIpGeoSecondary ?? undefined;
      }
    } catch (error) {
      Sentry.captureException(error);
    }
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
        Sentry.captureException(error);
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

const getViewsForTracker = async (
  threadId: string,
  userId: string
): Promise<null | View[]> => {
  const trackers = await prisma.tracker.findMany({
    where: { userId, threadId },
    // meed to sort the nested views
    include: { views: { orderBy: { createdAt: "desc" } } },
    orderBy: { createdAt: "desc" },
  });

  if (trackers.length === 0) {
    return null;
  }

  const cleanViews = (tracker: Tracker & { views: View[] }): View[] => {
    if (
      // we only clean when selfLoadMitigation===false (ie not null)
      tracker.selfLoadMitigation !== false ||
      // and there is at least one view
      tracker.views.length === 0
    ) {
      return tracker.views;
    }

    // sorted desc so last should be first to happen
    const firstView = tracker.views[tracker.views.length - 1];
    const timeFromTrackToViewSec = dayjs(firstView.createdAt).diff(
      dayjs(tracker.createdAt),
      "second",
      true
    );

    // TODO: const this
    if (timeFromTrackToViewSec < 10) {
      return tracker.views.slice(0, -1);
    }
    return tracker.views;
  };

  const views = trackers
    .flatMap((tracker) => cleanViews(tracker))
    // since we are not getting this from db due to flatmap
    .sort((a, b) => -(a.createdAt.getTime() - b.createdAt.getTime()));

  return views;
};

app.options("/api/v1/threads/:threadId/views/", corsMiddleware);
app.get(
  "/api/v1/threads/:threadId/views/",
  corsMiddleware,
  ...UseJwt,
  param("threadId").isString(),
  async (req: JWTRequest, res: Response): Promise<void> => {
    if (!req.auth || !req.auth.sub) {
      res.status(401).send(JSON.stringify({}));
      return;
    }

    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      res.status(400).json({ errors: errors.array() });
      return;
    }
    const data = matchedData(req);
    const threadId = String(data.threadId);
    const userIdAuth = req.auth.sub;

    const views = await getViewsForTracker(threadId, userIdAuth);

    if (views === null) {
      res.send(JSON.stringify({ views: null, error_code: "unknown_tracker" }));
      return;
    }

    res.send(JSON.stringify({ data: views }));
    return;
  }
);

app.options("/api/v1/views/", corsMiddleware);
app.get(
  "/api/v1/views/",
  corsMiddleware,
  ...UseJwt,
  query("userId").isString().isUUID(),
  async (req: JWTRequest, res: Response): Promise<void> => {
    if (!req.auth || !req.auth.sub) {
      res.status(401).send(JSON.stringify({}));
      return;
    }

    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      res.status(400).json({ errors: errors.array() });
      return;
    }
    const data = matchedData(req);
    const userId = data.userId as string;

    const userIdAuth = req.auth.sub;
    if (userIdAuth !== userId) {
      res.status(403).json({});
      return;
    }

    const views = await prisma.view.findMany({
      where: { tracker: { userId } },
      orderBy: { createdAt: "desc" },
      include: { tracker: { select: { threadId: true, emailSubject: true } } },
    });

    //TODO: filter out self views here

    res.send(JSON.stringify({ data: views }));
    return;
  }
);

app.options("/api/v1/trackers/", corsMiddleware);
app.post(
  "/api/v1/trackers/",
  corsMiddleware,
  ...UseJwt,
  body("trackId").isString().isUUID(),
  body("threadId").isString(),
  body("emailId").isString(),
  body("emailSubject").isString(),
  body("scheduledTimestamp").isInt({ gt: 0 }).optional(),
  body("selfLoadMitigation").isBoolean().optional(),
  async (req: JWTRequest, res: Response): Promise<void> => {
    if (!req.auth || !req.auth.sub) {
      res.status(401).send(JSON.stringify({}));
      return;
    }

    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      res.status(400).json({ errors: errors.array() });
      return;
    }

    const data = matchedData(req);
    const {
      trackId,
      threadId,
      emailId,
      emailSubject,
      scheduledTimestamp,
      selfLoadMitigation,
    } = data;

    if (trackId) {
      const userId = req.auth.sub;
      const clientIp = req.ip;

      const scheduledSendAt =
        scheduledTimestamp == null ? null : new Date(scheduledTimestamp);

      await prisma.tracker.create({
        data: {
          userId,
          trackId,
          threadId,
          emailId,
          emailSubject,
          scheduledSendAt,
          clientIp,
          selfLoadMitigation,
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

type UserData = {
  accessToken: string;
  expiresIn: number;
  emailAccount: string;
  trackingSlug: string;
  emailToken: string;
};

app.get(
  "/magic-login",
  query("token").isString().isUUID(),
  async (req: Request, res: Response): Promise<void> => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      res.status(400).json({ errors: errors.array() });
      return;
    }

    if (req.session == null) {
      res.status(500);
      return;
    }

    const data = matchedData(req);
    const token = data.token as string;

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

    // We are creating the access token at login time
    // and then we save it off on the session
    const userId = magicLinkToken.userId;
    const subject = String(userId);
    const { email, slug } = magicLinkToken.user;

    const expiresIn = env.ACCESS_TOKEN_EXPIRES_HOURS * 60 * 60;

    const accessToken = await jsonwebtoken.sign(
      {},
      env.JWT_ACCESS_TOKEN_SECRET,
      {
        algorithm: JWT_ALGORITHM,
        expiresIn,
        subject,
      }
    );

    const userData: UserData = {
      accessToken,
      expiresIn,
      emailAccount: email,
      trackingSlug: slug,
      // warty to track this:
      emailToken: token,
    };

    const currentUsers = (req.session.users as UserData[] | undefined) ?? [];

    const otherUsers = currentUsers.filter(
      (currentUser) => currentUser.emailAccount !== userData.emailAccount
    );
    req.session.users = [userData, ...otherUsers];

    res.status(200).send("Logging in...");

    // We could do a redirect here to a page that the Chrome extension would use
    // That way errors are surfaced

    return;
  }
);

// this logouts from everything
app.get("/logout", (req: Request, res: Response): void => {
  req.session = null;
  // <script>setTimeout(function() { top.window.close() }, 1);</script>
  res.status(200).send("You are logged out. You may close this window.");
});

app.get("/logged-in", (req: Request, res: Response): void => {
  res.status(200).send("You are logged in. You may close this window.");
  return;
});

const ROUTE_LOGIN_REQUEST_MAGIC = "/api/v1/login/request-magic";
app.options(ROUTE_LOGIN_REQUEST_MAGIC, corsMiddleware);
app.post(
  ROUTE_LOGIN_REQUEST_MAGIC,
  corsMiddleware,
  express.urlencoded({ extended: false }),
  body("email").isString().isEmail({ domain_specific_validation: true }),
  async (req: Request, res: Response): Promise<void> => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      res.status(400).json({ errors: errors.array() });
      return;
    }

    // Read this off before sending the response
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
        expiresAt: dayjs().add(env.MAGIC_TOKEN_EXPIRES_HOURS, "hour").toDate(),
      },
    });

    const loginUrl = `${protocol}://${host}/magic-login?token=${magicLinkToken.token}`;

    const msg = {
      to: user.email,
      from: {
        email: env.MAGIC_LINK_FROM_EMAIL,
        name: env.MAGIC_LINK_FROM_NAME,
      },
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
      Sentry.captureException(error);

      console.error(error);

      if (error.response) {
        console.error(error.response.body);
      }
    }

    return;
  }
);

// The name of this can change now that is just returns the token
// Also it might not need to be a POST
// Do we care about allowing this to only be run once?
// Also a bit weird that we key this off the original email token.
app.options("/api/v1/login/use-magic", corsMiddleware);
app.post(
  "/api/v1/login/use-magic",
  corsMiddleware,
  body("token").isString().isUUID(),
  async (req: Request, res: Response): Promise<void> => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      res.status(400).json({ errors: errors.array() });
      return;
    }

    const token = req.body.token as string;

    if (req.session == null) {
      res.status(500);
      return;
    }

    // This can be called more than once and just reads off the session
    // A little hacky
    const userData = ((req.session.users ?? []) as UserData[]).find(
      (user) => user.emailToken == token
    );

    if (userData === undefined) {
      res.status(403);
      return;
    }

    res.status(200).json(userData);
    return;
  }
);

app.post(
  "/api/v1/me",
  corsMiddleware,
  ...UseJwt,
  async (req: JWTRequest, res: Response): Promise<void> => {
    if (!req.auth || !req.auth.sub) {
      res.status(401).send(JSON.stringify({}));
      return;
    }

    const user = await prisma.user.findFirst({ where: { id: req.auth.sub } });
    if (!user) {
      res.status(403).send(JSON.stringify({}));
      return;
    }

    res.send(
      JSON.stringify({
        data: {
          id: user.id,
          emailAccount: user.email,
          trackingSlug: user.slug,
        },
      })
    );
  }
);

// Probably not needed long term
app.get("/ping", (req: Request, res: Response): void => {
  res.status(200).send("");
});

app.options("/api/v1/stunnel", corsMiddleware);
app.post(
  "/api/v1/stunnel",
  corsMiddleware,
  express.text(),
  sentryTunnelHandler
);

// See https://github.com/oauthjs/node-oauth2-server for specification
const OAuthServerModel: AuthorizationCodeModel = {
  getClient: async (clientId: string, clientSecret?: string) => {
    if (clientId !== env.GMAIL_ADDON_CLIENT_ID) {
      return null;
    }
    if (
      clientSecret &&
      env.GMAIL_ADDON_CLIENT_SECRET.length !== clientSecret.length
    )
      return null;

    if (
      clientSecret &&
      !crypto.timingSafeEqual(
        Buffer.from(env.GMAIL_ADDON_CLIENT_SECRET),
        Buffer.from(clientSecret)
      )
    )
      return null;

    return {
      id: env.GMAIL_ADDON_CLIENT_ID,
      grants: ["authorization_code"],
      redirectUris: [env.GMAIL_ADDON_REDIRECT_URI],
    };
  },
  generateAccessToken: async (client, user, scope) => {
    return user.accessToken;
  },
  getAuthorizationCode: async (
    authorizationCode
  ): Promise<AuthorizationCode> => {
    // here we just parse the jwt that send out
    // we should verify
    const data = jsonwebtoken.decode(authorizationCode);
    if (data === null || typeof data === "string") {
      throw Error();
    }
    const { client, user, expiresAt: expiresAtNum, redirectUri } = data;

    return {
      authorizationCode,
      client,
      user,
      expiresAt: new Date(expiresAtNum),
      redirectUri,
    };
  },
  revokeAuthorizationCode: async () => {
    // we can't currently revoke as this is stateless
    return true;
  },
  verifyScope: async (): Promise<never> => {
    //https://oauth2-server.readthedocs.io/en/latest/model/spec.html#verifyscope-accesstoken-scope-callback
    throw Error();
  },
  // we should use a real auth code and not this BS
  saveAuthorizationCode: async (
    code,
    client,
    user
  ): Promise<AuthorizationCode> => {
    const authorizationCode = await jsonwebtoken.sign(
      {
        redirectUri: code.redirectUri,
        expiresAt: code.expiresAt.getTime(),
        client,
        user,
      },
      env.JWT_ACCESS_TOKEN_SECRET,
      {
        algorithm: JWT_ALGORITHM,
        // Should we track any of these?
        // expiresIn,
        // subject,
      }
    );
    return {
      ...code,
      authorizationCode,
      client,
      user,
    };
  },
  getAccessToken: async (accessToken): Promise<never> => {
    //https://oauth2-server.readthedocs.io/en/latest/model/spec.html#getaccesstoken-accesstoken-callback
    throw Error();
  },
  saveToken: async (token, client, user) => {
    // no need to save if we are using jwt accessToken
    // we can't send anything extra here at least the lib on google doesn't support
    return { accessToken: token.accessToken, client, user };
  },
};

const oauth = new OAuthServer({
  model: OAuthServerModel,
  authenticateHandler: {
    handle: (request: Request, response: Response): User => {
      // just bomb here if this is bad as we are checking upstream
      return response.locals.login_hint_user;
    },
  },
});

app.get(
  "/o/oauth2/auth",
  query("login_hint").isString().isEmail({ domain_specific_validation: true }),
  (request, response, next) => {
    const errors = validationResult(request);
    if (!errors.isEmpty()) {
      response.status(400).json({ errors: errors.array() });
      return;
    }
    const data = matchedData(request);
    const login_hint = data.login_hint as string;

    if (request.session == null) {
      response.status(500);
      return;
    }

    // use the query param `login_hint` to to identify the user
    // this is a "silent" auth in that we don't prompt the user for anything
    const login_hint_user = ((request.session.users ?? []) as UserData[]).find(
      (user) => user.emailAccount == login_hint
    );

    if (login_hint_user === undefined) {
      const errorContents =
        `You are not currently logged in as: ${login_hint}` +
        `<form enctype="application/x-www-form-urlencoded" method="post" action="${ROUTE_LOGIN_REQUEST_MAGIC}">` +
        `<input type="hidden" name="email" value="${login_hint}">` +
        `<input type="submit" value="Login">` +
        `</form>`;
      response.send(errorContents);
      return;
    }

    response.locals.login_hint_user = login_hint_user;
    next();
  },
  oauth.authorize()
);
app.post(
  "/o/oauth2/token",
  express.urlencoded({ extended: false }),
  oauth.token()
);

// The error handler must be before any other error middleware and after all controllers
app.use(Sentry.Handlers.errorHandler());

// -------------------------------------------------

app.listen(env.PORT, async () => {
  console.log(`[server]: Server is running on ${env.PORT}`);
});
