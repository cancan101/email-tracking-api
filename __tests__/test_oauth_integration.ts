import request from "supertest";
import { randomUUID } from "crypto";

import { app } from "../src/app";
import { prismaMock } from "../src/singleton";

// End-to-end check that the magic-login flow plants `id` into the
// cookie-session, and that a subsequent /o/oauth2/auth round-trip reaches
// saveAuthorizationCode with that id intact.

describe("magic-login → OAuth integration", () => {
  test("session minted by /magic-login carries id into saveAuthorizationCode", async () => {
    const userId = "71cf7000-cf96-47b4-bc9f-bf36f486a088";
    const userEmail = "alice@example.com";
    const token = randomUUID();

    // Mock the magic-link token lookup + mark-used + access-token mint.
    prismaMock.magicLinkToken.findFirst.mockResolvedValue({
      id: "tok-row-id",
      createdAt: new Date(),
      token,
      userId,
      expiresAt: new Date(Date.now() + 60_000),
      usedAt: null,
      // @ts-expect-error include shape
      user: { email: userEmail, slug: "slug-uuid" },
    });
    prismaMock.magicLinkToken.update.mockResolvedValue({} as any);

    // Mock authorization-code insert so we can inspect what would be written.
    prismaMock.authorizationCode.create.mockResolvedValue({
      code: "x",
      clientId: "client-1",
      userId,
      redirectUri: "https://test.local",
      scope: [],
      expiresAt: new Date(Date.now() + 60_000),
      createdAt: new Date(),
      consumedAt: null,
    });

    const agent = request.agent(app);

    // 1. /magic-login plants the session
    const loginRes = await agent.get(`/magic-login?token=${token}`);
    expect(loginRes.status).toEqual(200);
    expect(loginRes.headers["set-cookie"]).toBeDefined();

    // 2. /o/oauth2/auth with the session and matching login_hint
    const authRes = await agent.get("/o/oauth2/auth").query({
      login_hint: userEmail,
      response_type: "code",
      client_id: process.env.GMAIL_ADDON_CLIENT_ID ?? "CLIENT_ID",
      redirect_uri:
        process.env.GMAIL_ADDON_REDIRECT_URI ?? "https://test.local",
      state: "xyz",
    });

    // The oauth library will redirect (302) with the code on success, or
    // 4xx/5xx if something is wrong. We want to assert that *if* the model
    // was called, it received the real UUID — not "undefined".
    if (prismaMock.authorizationCode.create.mock.calls.length > 0) {
      const writtenData =
        prismaMock.authorizationCode.create.mock.calls[0][0].data;
      expect(writtenData.userId).toEqual(userId);
      expect(writtenData.userId).not.toEqual("undefined");
    } else {
      // If create wasn't called, surface why for debugging.
      throw new Error(
        `saveAuthorizationCode was not reached. /o/oauth2/auth status=${authRes.status} body=${JSON.stringify(authRes.body)} text=${authRes.text.slice(0, 500)}`,
      );
    }
  });
});
