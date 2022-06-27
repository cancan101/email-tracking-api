// https://github.com/getsentry/examples/blob/c098c2bd97fbb15351a5206df41c4aff959b3b0a/tunneling/nextjs/pages/api/tunnel.js
import * as Sentry from "@sentry/node";
import * as urlLib from "url";
import { Request, Response } from "express";
import env from "./settings";

const sentryHost = env.SENTRY_HOST_EXTENSION;

// Set knownProjectIds to an array with your Sentry project IDs which you
// want to accept through this proxy.
const knownProjectIds = [env.SENTRY_PROJECT_ID_EXTENSION];

// -------------------------------------------------

const sentryTunnelHandler = async (
  req: Request,
  res: Response
): Promise<void> => {
  try {
    const envelope = req.body;
    const pieces = envelope.split("\n");

    const header = JSON.parse(pieces[0]);

    const { host, path } = urlLib.parse(header.dsn);
    if (host !== sentryHost) {
      throw new Error(`invalid host: ${host}`);
    }

    if (path === null) {
      throw new Error(`invalid dsn: ${header.dsn}`);
    }

    const projectId = path.endsWith("/")
      ? path.slice(0, -1)
      : path.startsWith("/")
      ? path.slice(1)
      : path;
    if (!knownProjectIds.includes(projectId)) {
      throw new Error(`invalid project id: ${projectId}`);
    }

    const url = `https://${sentryHost}/api/${projectId}/envelope/`;
    const response = await fetch(url, {
      method: "POST",
      body: envelope,
    });
    res.json(response.json());
    return;
  } catch (e) {
    Sentry.captureException(e);
    res.status(400).json({ status: "invalid request" });
    return;
  }
};

export default sentryTunnelHandler;
