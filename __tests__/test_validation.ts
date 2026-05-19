import request from "supertest";

import { app, getAccessToken } from "../src/app";

const userId = "71cf7000-cf96-47b4-bc9f-bf36f486a088";

describe("zod validation on /api/v1/trackers/", () => {
  test("rejects a trackId that isn't a UUID", async () => {
    const { accessToken } = await getAccessToken(userId);
    const response = await request(app)
      .post(`/api/v1/trackers/`)
      .send({
        trackId: "not-a-uuid",
        threadId: "thread",
        emailId: "msg",
        emailSubject: "subj",
      })
      .set("Authorization", `Bearer ${accessToken}`);
    expect(response.status).toEqual(400);
    expect(response.body.errors).toBeDefined();
  });

  test("rejects an emailSubject over the length cap", async () => {
    const { accessToken } = await getAccessToken(userId);
    const response = await request(app)
      .post(`/api/v1/trackers/`)
      .send({
        trackId: "4fcb3ce6-bc89-47c8-9ed2-4fbaaab2620e",
        threadId: "thread",
        emailId: "msg",
        emailSubject: "x".repeat(1001),
      })
      .set("Authorization", `Bearer ${accessToken}`);
    expect(response.status).toEqual(400);
    const paths = response.body.errors.map((e: { path: string }) => e.path);
    expect(paths).toContain("emailSubject");
  });
});

describe("zod validation on /api/v1/views/", () => {
  test("rejects a non-UUID userId", async () => {
    const { accessToken } = await getAccessToken(userId);
    const response = await request(app)
      .get(`/api/v1/views/?userId=not-a-uuid`)
      .set("Authorization", `Bearer ${accessToken}`);
    expect(response.status).toEqual(400);
  });

  test("rejects a non-numeric limit", async () => {
    const { accessToken } = await getAccessToken(userId);
    const response = await request(app)
      .get(`/api/v1/views/?userId=${userId}&limit=abc`)
      .set("Authorization", `Bearer ${accessToken}`);
    expect(response.status).toEqual(400);
  });

  test("accepts a format-valid UUID that doesn't satisfy RFC version bits", async () => {
    // Pre-#714, isUUID() accepted any 8-4-4-4-12 hex string. zod's .uuid()
    // enforces RFC version/variant bits (position 14 must be 1-8, position
    // 19 must be 8/9/a/b). Some historical user rows have version=0 and/or
    // variant=0, so the userId schema uses a regex to match the old loose
    // behavior. This fixture has 0 in both positions.
    const looseUserId = "feedface-cafe-0bad-0ddd-deadbeefcafe";
    const { accessToken } = await getAccessToken(userId);
    const response = await request(app)
      .get(`/api/v1/views/?userId=${looseUserId}&limit=20`)
      .set("Authorization", `Bearer ${accessToken}`);
    expect(response.status).not.toEqual(400);
  });
});
