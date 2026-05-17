import { OAuthServerModel } from "../src/app";
import { prismaMock } from "../src/singleton";

const baseCode = {
  code: "abc-uuid-code",
  clientId: "client-1",
  userId: "71cf7000-cf96-47b4-bc9f-bf36f486a088",
  redirectUri: "https://example.com/cb",
  scope: [],
  expiresAt: new Date(Date.now() + 60_000),
  createdAt: new Date(),
  consumedAt: null,
};

describe("OAuthServerModel.getAuthorizationCode", () => {
  test("returns the code when it is valid", async () => {
    prismaMock.authorizationCode.findUnique.mockResolvedValue(baseCode);

    const result = await OAuthServerModel.getAuthorizationCode("abc-uuid-code");
    if (!result) throw new Error("expected a truthy AuthorizationCode");
    expect(result.authorizationCode).toEqual("abc-uuid-code");
    expect(result.user).toEqual({ id: baseCode.userId });
    expect(result.client.id).toEqual("client-1");
  });

  test("throws when the code is unknown", async () => {
    prismaMock.authorizationCode.findUnique.mockResolvedValue(null);

    await expect(OAuthServerModel.getAuthorizationCode("nope")).rejects.toThrow(
      /invalid/,
    );
  });

  test("throws when the code has already been consumed", async () => {
    prismaMock.authorizationCode.findUnique.mockResolvedValue({
      ...baseCode,
      consumedAt: new Date(),
    });

    await expect(
      OAuthServerModel.getAuthorizationCode("abc-uuid-code"),
    ).rejects.toThrow(/already used/);
  });

  test("throws when the code is past expiry", async () => {
    prismaMock.authorizationCode.findUnique.mockResolvedValue({
      ...baseCode,
      expiresAt: new Date(Date.now() - 60_000),
    });

    await expect(
      OAuthServerModel.getAuthorizationCode("abc-uuid-code"),
    ).rejects.toThrow(/expired/);
  });
});

describe("OAuthServerModel.revokeAuthorizationCode", () => {
  test("returns true when exactly one row is marked consumed", async () => {
    prismaMock.authorizationCode.updateMany.mockResolvedValue({ count: 1 });

    const ok = await OAuthServerModel.revokeAuthorizationCode({
      authorizationCode: "abc",
      expiresAt: new Date(),
      redirectUri: "x",
      client: { id: "c", grants: [] },
      user: { id: "u" },
    });
    expect(ok).toBe(true);

    // Confirm it filters by consumedAt: null so a concurrent revoke can't
    // double-mark.
    expect(prismaMock.authorizationCode.updateMany).toHaveBeenCalledWith(
      expect.objectContaining({
        where: expect.objectContaining({ consumedAt: null }),
      }),
    );
  });

  test("returns false when no eligible row exists", async () => {
    prismaMock.authorizationCode.updateMany.mockResolvedValue({ count: 0 });

    const ok = await OAuthServerModel.revokeAuthorizationCode({
      authorizationCode: "abc",
      expiresAt: new Date(),
      redirectUri: "x",
      client: { id: "c", grants: [] },
      user: { id: "u" },
    });
    expect(ok).toBe(false);
  });
});

describe("OAuthServerModel.saveAuthorizationCode", () => {
  test("inserts the code into the database and echoes it back", async () => {
    prismaMock.authorizationCode.create.mockResolvedValue(baseCode);

    const result = await OAuthServerModel.saveAuthorizationCode(
      {
        authorizationCode: "(library-supplied-but-ignored)",
        expiresAt: new Date(Date.now() + 60_000),
        redirectUri: "https://example.com/cb",
      },
      { id: "client-1", grants: ["authorization_code"] },
      { id: "71cf7000-cf96-47b4-bc9f-bf36f486a088" },
    );

    expect(prismaMock.authorizationCode.create).toHaveBeenCalledTimes(1);
    // Confirm the row we'd write to Postgres has a real UUID userId, not
    // the string "undefined" (the regression that prompted this hardening).
    expect(prismaMock.authorizationCode.create).toHaveBeenCalledWith(
      expect.objectContaining({
        data: expect.objectContaining({
          userId: "71cf7000-cf96-47b4-bc9f-bf36f486a088",
        }),
      }),
    );
    // The handler mints its own opaque code; we don't pass through the
    // library's input value.
    if (!result) throw new Error("expected a truthy AuthorizationCode");
    expect(result.authorizationCode).toMatch(
      /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i,
    );
  });

  test("throws when the user object has no id", async () => {
    await expect(
      OAuthServerModel.saveAuthorizationCode(
        {
          authorizationCode: "x",
          expiresAt: new Date(Date.now() + 60_000),
          redirectUri: "https://example.com/cb",
        },
        { id: "client-1", grants: ["authorization_code"] },
        // No `id` — this is what the session looked like before this fix.
        {} as { id: string },
      ),
    ).rejects.toThrow(/user missing id/);
    expect(prismaMock.authorizationCode.create).not.toHaveBeenCalled();
  });

  test("throws when the client object has no id", async () => {
    await expect(
      OAuthServerModel.saveAuthorizationCode(
        {
          authorizationCode: "x",
          expiresAt: new Date(Date.now() + 60_000),
          redirectUri: "https://example.com/cb",
        },
        {} as { id: string; grants: string[] },
        { id: "71cf7000-cf96-47b4-bc9f-bf36f486a088" },
      ),
    ).rejects.toThrow(/client missing id/);
  });
});
