import request from "supertest";
import { randomUUID } from "crypto";

// Mock the geo lookup so the pixel handler doesn't try to reach ip-api.com
// from the test runner. Returning null is equivalent to "all providers
// failed" and is one of the documented happy-ish paths through the code.
jest.mock("../src/client-info", () => ({
  getClientIpGeo: jest.fn().mockResolvedValue(null),
}));

import { Prisma } from "@prisma/client";
import { app } from "../src/app";
import { prismaMock } from "../src/singleton";

const TRACK_ID = "4fcb3ce6-bc89-47c8-9ed2-4fbaaab2620e";
const TRACKING_SLUG = "9a1b2c3d-4e5f-6a7b-8c9d-0e1f2a3b4c5d";

describe("pixel handler /t/:trackingSlug/:trackId/image.gif", () => {
  test("serves the transparent gif and inserts a view on a valid trackId", async () => {
    prismaMock.view.create.mockResolvedValue({} as never);

    const response = await request(app).get(
      `/t/${TRACKING_SLUG}/${TRACK_ID}/image.gif`,
    );

    expect(response.status).toEqual(200);
    expect(response.headers["content-type"]).toMatch(/image\/gif/);
    // The pixel is a 43-byte transparent 1x1 gif.
    expect(parseInt(response.headers["content-length"], 10)).toBeGreaterThan(0);
    expect(prismaMock.view.create).toHaveBeenCalledTimes(1);
    expect(prismaMock.view.create).toHaveBeenCalledWith(
      expect.objectContaining({
        data: expect.objectContaining({ trackId: TRACK_ID }),
      }),
    );
  });

  test("still serves the gif but skips view insert when params are not UUIDs", async () => {
    const response = await request(app).get(
      `/t/not-a-uuid/also-not-a-uuid/image.gif`,
    );

    expect(response.status).toEqual(200);
    expect(response.headers["content-type"]).toMatch(/image\/gif/);
    expect(prismaMock.view.create).not.toHaveBeenCalled();
  });

  test("swallows the P2003 FK error for an unknown trackId without 500ing", async () => {
    prismaMock.view.create.mockRejectedValue(
      // Construct a known-request error that matches the code's narrow catch.
      new Prisma.PrismaClientKnownRequestError("FK violation", {
        code: "P2003",
        clientVersion: "test",
        meta: { field_name: "View_trackId_fkey (index)" },
      }),
    );

    const response = await request(app).get(
      `/t/${TRACKING_SLUG}/${TRACK_ID}/image.gif`,
    );

    expect(response.status).toEqual(200);
    expect(response.headers["content-type"]).toMatch(/image\/gif/);
  });

  test("does not 500 the response even if the DB write throws an unexpected error", async () => {
    prismaMock.view.create.mockRejectedValue(new Error("boom"));

    const response = await request(app).get(
      `/t/${TRACKING_SLUG}/${TRACK_ID}/image.gif`,
    );

    // The pixel is sent BEFORE the DB write, so the response stays 200 even
    // when the write blows up. Client correctness > telemetry completeness
    // on this hot path.
    expect(response.status).toEqual(200);
    expect(response.headers["content-type"]).toMatch(/image\/gif/);
  });
});

describe("deprecated /image.gif", () => {
  test("serves the gif on a valid trackId query param", async () => {
    prismaMock.view.create.mockResolvedValue({} as never);

    const response = await request(app).get(
      `/image.gif?trackId=${randomUUID()}`,
    );

    expect(response.status).toEqual(200);
    expect(response.headers["content-type"]).toMatch(/image\/gif/);
  });

  test("still serves the gif without trackId", async () => {
    const response = await request(app).get(`/image.gif`);

    expect(response.status).toEqual(200);
    expect(response.headers["content-type"]).toMatch(/image\/gif/);
    expect(prismaMock.view.create).not.toHaveBeenCalled();
  });
});
