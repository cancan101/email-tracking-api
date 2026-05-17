import request from "supertest";

import { app } from "../src/app";
import { prismaMock } from "../src/singleton";

describe("XSS in /o/oauth2/auth login_hint", () => {
  // The express-validator isEmail() check is the first line of defense — a
  // payload like `"><script>` won't get past it. But isEmail permits HTML
  // special characters in the local part (`&`, `'`), so escaping the rendered
  // value is still required.
  test("html-escapes special characters in a valid email login_hint", async () => {
    const payload = `a&b'c@example.com`;
    const response = await request(app)
      .get(`/o/oauth2/auth`)
      .query({ login_hint: payload });

    expect(response.status).toEqual(200);
    expect(response.text).not.toContain(payload);
    expect(response.text).toContain("a&amp;b&#39;c@example.com");
  });
});

describe("CSRF on /logout", () => {
  test("rejects GET", async () => {
    const response = await request(app).get("/logout");
    expect(response.status).toEqual(404);
  });

  test("accepts POST", async () => {
    const response = await request(app).post("/logout");
    expect(response.status).toEqual(200);
  });
});

describe("Rate limit on /api/v1/login/request-magic", () => {
  test("returns 429 after the per-IP burst is exhausted", async () => {
    // findFirst returns null for an unknown email; handler still returns 200
    // before the lookup, but rate-limit middleware runs first.
    prismaMock.user.findFirst.mockResolvedValue(null);

    const url = "/api/v1/login/request-magic";
    // Per-IP limit is 20/15min. Send 21 requests; the 21st must be 429.
    let lastStatus = 0;
    for (let i = 0; i < 21; i++) {
      const res = await request(app)
        .post(url)
        .send({ email: `user${i}@example.com` });
      lastStatus = res.status;
    }
    expect(lastStatus).toEqual(429);
  });
});
