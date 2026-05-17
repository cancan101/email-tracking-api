import request from "supertest";

import { app } from "../src/app";
import { prismaMock } from "../src/singleton";

describe("XSS in /o/oauth2/auth login_hint", () => {
  // Defense in depth: the zod email schema is the first line and rejects
  // anything that contains HTML-special characters (zod is stricter than the
  // old express-validator isEmail, which permitted `&` and `'` in the local
  // part). The escapeHtml() call in the handler is a second line in case
  // validation is ever loosened or bypassed.
  test("rejects login_hint with HTML-special characters before rendering", async () => {
    const response = await request(app)
      .get(`/o/oauth2/auth`)
      .query({ login_hint: `a&b'c@example.com` });

    expect(response.status).toEqual(400);
  });

  test("rejects login_hint with quote/script payload", async () => {
    const response = await request(app)
      .get(`/o/oauth2/auth`)
      .query({ login_hint: `x"><script>alert(1)</script>@example.com` });

    expect(response.status).toEqual(400);
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
