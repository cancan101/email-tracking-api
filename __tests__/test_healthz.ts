import request from "supertest";

import { app } from "../src/app";
import { prismaMock } from "../src/singleton";

describe("/healthz", () => {
  test("returns 200 with status ok when DB probe succeeds", async () => {
    prismaMock.$queryRaw.mockResolvedValue([{ "?column?": 1 }]);

    const response = await request(app).get("/healthz");

    expect(response.status).toEqual(200);
    expect(response.body).toEqual({ status: "ok" });
  });

  test("returns 503 when DB probe fails", async () => {
    prismaMock.$queryRaw.mockRejectedValue(new Error("connection refused"));

    const response = await request(app).get("/healthz");

    expect(response.status).toEqual(503);
    expect(response.body).toEqual(
      expect.objectContaining({ status: "degraded" }),
    );
  });
});

describe("/ping", () => {
  test("returns 200 without touching the DB (liveness only)", async () => {
    const response = await request(app).get("/ping");
    expect(response.status).toEqual(200);
    expect(prismaMock.$queryRaw).not.toHaveBeenCalled();
  });
});
