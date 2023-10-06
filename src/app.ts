import express, { Request, Response, NextFunction } from "express";
import path from "path";
import cors, { CorsOptions } from "cors";
import { Prisma, View, Tracker } from "@prisma/client";
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
import OAuthServer from "@node-oauth/express-oauth-server";
import {
  AuthorizationCodeModel,
  AuthorizationCode,
  User,
} from "@node-oauth/oauth2-server";
import cookieSession from "cookie-session";
import crypto from "crypto";
import nocache from "nocache";

import sentryTunnelHandler from "./sentry-tunnel";
import env from "./settings";
import { getClientIpGeo } from "./client-info";
import prisma from "./client";

// -------------------------------------------------

const app = express();

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

// TODO(cancan101): This should be on just the routes that need it
app.use(
  cookieSession({
    secret: env.COOKIE_SESSION_SECRET,

    // Cookie Options
    sameSite: "lax",
    secure: env.COOKIE_SESSION_SECURE,
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

async function processImage(
  trackId: string,
  req: Request,
  res: Response
): Promise<void> {
  const clientIp = req.ip;
  const userAgent = req.headers["user-agent"];

  const clientIpGeo = await getClientIpGeo(clientIp, userAgent);

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
    if (
      error instanceof Prisma.PrismaClientKnownRequestError &&
      error.code === "P2003" &&
      error.meta?.field_name === "View_trackId_fkey (index)"
    ) {
      console.log("Unknown tracker requested", trackId);
    } else {
      Sentry.captureException(error);
      console.error(error);
    }
  }
  return;
}

async function imageRoute(req: Request, res: Response): Promise<void> {
  res.sendFile(transparentGifPath, { lastModified: false });

  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    // Just send the image in this case
    return;
  }
  const data = matchedData(req);
  const trackId = data.trackId as string;

  await processImage(trackId, req, res);
}

// Deprecated
app.get(
  "/image.gif",
  nocache(),
  query("trackId").isString().isUUID(),
  async (req: Request, res: Response): Promise<void> => {
    await imageRoute(req, res);
  }
);

app.get(
  "/t/:trackingSlug/:trackId/image.gif",
  nocache(),
  param("trackingSlug").isString().isUUID(),
  param("trackId").isString().isUUID(),
  async (req: Request, res: Response): Promise<void> => {
    await imageRoute(req, res);
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

  const cleanViews = (
    tracker: Tracker & { views: View[] }
  ): (View & { tracker: Tracker })[] => {
    const { views: viewsRaw, ...trackerNoViews } = tracker;
    const views = viewsRaw.map((view) => ({
      ...view,
      tracker: trackerNoViews,
    }));
    if (
      // we only clean when selfLoadMitigation===false (ie not null)
      tracker.selfLoadMitigation !== false ||
      // and there is at least one view
      views.length === 0
    ) {
      return views;
    }

    // sorted desc so last should be first to happen
    const firstView = views[views.length - 1];
    const timeFromTrackToViewSec = dayjs(firstView.createdAt).diff(
      dayjs(tracker.createdAt),
      "second",
      true
    );

    if (timeFromTrackToViewSec < env.SELF_VIEW_THRESHOLD_SEC) {
      return views.slice(0, -1);
    }
    return views;
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
      res.status(401).json({});
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
      res.json({ views: null, error_code: "unknown_tracker" });
      return;
    }

    res.json({ data: views });
    return;
  }
);

app.options("/api/v1/views/", corsMiddleware);
app.get(
  "/api/v1/views/",
  corsMiddleware,
  ...UseJwt,
  query("userId").isString().isUUID(),
  query("limit").isInt({ gt: 0 }).optional(),
  async (req: JWTRequest, res: Response): Promise<void> => {
    if (!req.auth || !req.auth.sub) {
      res.status(401).json({});
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

    let viewsRaw;
    try {
      viewsRaw = await prisma.view.findMany({
        where: { tracker: { userId } },
        orderBy: { createdAt: "desc" },
        include: {
          tracker: {
            select: {
              threadId: true,
              emailSubject: true,
              selfLoadMitigation: true,
              createdAt: true,
            },
          },
        },
        take: data.limit == null ? undefined : parseInt(data.limit, 10),
      });
    } catch (error) {
      if (
        error instanceof Prisma.PrismaClientKnownRequestError &&
        // https://www.prisma.io/docs/reference/api-reference/error-reference#error-codes
        error.code === "P1001"
      ) {
        console.log("Can't reach database server");
        res.status(503).json({});
        return;
      } else {
        Sentry.captureException(error);
        console.error(error);

        res.status(500).json({});
        return;
      }
    }

    // TODO: push this into SQL so that the limit clause is correct
    const views = viewsRaw.filter(
      (view) =>
        view.tracker.selfLoadMitigation !== false ||
        dayjs(view.createdAt).diff(
          dayjs(view.tracker.createdAt),
          "second",
          true
        ) >= env.SELF_VIEW_THRESHOLD_SEC
    );

    res.json({ data: views });
    return;
  }
);

const parseScheduledSendAt = (scheduledTimestamp: any): Date | null => {
  if (scheduledTimestamp == null) {
    return null;
  } else if (typeof scheduledTimestamp === "number") {
    return new Date(scheduledTimestamp);
  } else {
    return new Date(parseInt(scheduledTimestamp, 10));
  }
};

const getSessionUsers = (
  session: CookieSessionInterfaces.CookieSessionObject
): UserData[] => {
  return (session.users as UserData[] | undefined) ?? [];
};

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
      res.status(401).json({});
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

      const scheduledSendAt = parseScheduledSendAt(scheduledTimestamp);

      if (scheduledSendAt !== null && isNaN(+scheduledSendAt)) {
        res.status(400).json({ error_code: "invalid_scheduledTimestamp" });
        return;
      }

      try {
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
      } catch (error) {
        if (
          error instanceof Prisma.PrismaClientKnownRequestError &&
          error.code === "P2002" &&
          // not sure if this needs a contains,
          // rather than assuming it is at index 0
          (error.meta?.target as string[] | undefined)?.[0] === "emailId"
        ) {
          console.log("emailId already tracked", trackId);
          res.status(409).json({});
          return;
        } else {
          Sentry.captureException(error);
          console.error(error);

          res.status(500).json({});
          return;
        }
      }
      res.status(201).json({});
      return;
    } else {
      res.status(400).json({});
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

async function getAccessToken(
  userId: string
): Promise<{ accessToken: string; expiresIn: number }> {
  const subject = String(userId);

  const expiresIn = env.ACCESS_TOKEN_EXPIRES_HOURS * 60 * 60;

  const accessToken = await jsonwebtoken.sign({}, env.JWT_ACCESS_TOKEN_SECRET, {
    algorithm: JWT_ALGORITHM,
    expiresIn,
    subject,
  });
  return { accessToken, expiresIn };
}

app.get(
  "/magic-login",
  query("token").isString().isUUID(),
  async (req: Request, res: Response): Promise<void> => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      res.status(400).json({ errors: errors.array() });
      return;
    }

    const session = req.session;
    if (session == null) {
      res.status(500).json({});
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
    const { accessToken, expiresIn } = await getAccessToken(userId);
    const { email, slug } = magicLinkToken.user;

    const userData: UserData = {
      accessToken,
      expiresIn,
      emailAccount: email,
      trackingSlug: slug,
      // warty to track this:
      emailToken: token,
    };

    const currentUsers = getSessionUsers(session);
    // splice out this email if we already track it
    const otherUsers = currentUsers.filter(
      (currentUser) => currentUser.emailAccount !== userData.emailAccount
    );
    session.users = [userData, ...otherUsers] as UserData[];

    res.status(200).send("Logging in...");

    // We could do a redirect here to a page that the Chrome extension would use
    // That way errors are surfaced

    return;
  }
);

// this logouts from everything
// TODO(cancan101): POST + csrf token (?)
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
    res.status(200).json({});

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

    const session = req.session;
    if (session == null) {
      res.status(500).json({});
      return;
    }
    // This can be called more than once and just reads off the session
    // A little hacky
    const userData = getSessionUsers(session).find(
      (user) => user.emailToken == token
    );

    if (userData === undefined) {
      res.status(403).json({});
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
      res.status(401).json({});
      return;
    }

    const user = await prisma.user.findFirst({ where: { id: req.auth.sub } });
    if (!user) {
      res.status(403).json({});
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
  express.text({ limit: env.SENTRY_TUNNEL_SIZE_LIMIT }),
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

    const session = request.session;
    if (session == null) {
      response.status(500).json({});
      return;
    }

    const currentUsers = getSessionUsers(session);

    // use the query param `login_hint` to to identify the user
    // this is a "silent" auth in that we don't prompt the user for anything
    const login_hint_user = currentUsers.find(
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

export { app, getAccessToken };
