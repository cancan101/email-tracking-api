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
});
