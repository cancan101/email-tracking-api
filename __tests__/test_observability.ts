import request from "supertest";

import { app } from "../src/app";

describe("request id middleware", () => {
  test("generates an x-request-id when none is supplied", async () => {
    const response = await request(app).get("/ping");
    expect(response.status).toEqual(200);
    const id = response.headers["x-request-id"];
    expect(id).toMatch(
      /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i,
    );
  });

  test("echoes back a client-supplied x-request-id", async () => {
    const supplied = "test-request-id-abc-123";
    const response = await request(app)
      .get("/ping")
      .set("x-request-id", supplied);
    expect(response.status).toEqual(200);
    expect(response.headers["x-request-id"]).toEqual(supplied);
  });
});
