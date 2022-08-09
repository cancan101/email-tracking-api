import request from "supertest";

import { app, getAccessToken } from "../src/app";
import { prismaMock } from "../src/singleton";

const mockView = {
  id: "a",
  clientIp: "",
  userAgent: "",
  trackId: "",
  createdAt: new Date(),
  clientIpGeo: null,
  tracker: {},
};

const mockViewNoSelfMitigationBad = {
  id: "a",
  clientIp: "",
  userAgent: "",
  trackId: "",
  createdAt: new Date("2021-01-01 12:00:00"),
  clientIpGeo: null,
  tracker: {
    selfLoadMitigation: false,
    createdAt: new Date("2021-01-01 12:00:00"),
  },
};

const mockViewNoSelfMitigationGood = {
  id: "a",
  clientIp: "",
  userAgent: "",
  trackId: "",
  createdAt: new Date("2021-01-01 13:00:00"),
  clientIpGeo: null,
  tracker: {
    selfLoadMitigation: false,
    createdAt: new Date("2021-01-01 12:00:00"),
  },
};

test("test views filtered by user", async () => {
  prismaMock.view.findMany.mockResolvedValue([mockView]);

  const userId = "71cf7000-cf96-47b4-bc9f-bf36f486a088";
  const { accessToken } = await getAccessToken(userId);

  const response = await request(app)
    .get(`/api/v1/views/?userId=${userId}`)
    .set("Authorization", `Bearer ${accessToken}`);

  expect(response.status).toEqual(200);
  expect(response.headers["content-type"]).toMatch(/json/);

  const responseJson = JSON.parse(response.text);
  expect(responseJson.data.length).toEqual(1);

  expect(prismaMock.view.findMany).toBeCalledWith(
    expect.not.objectContaining({ take: expect.anything() })
  );
});

test("test views filtered by user and with limit", async () => {
  prismaMock.view.findMany.mockResolvedValue([mockView]);

  const userId = "71cf7000-cf96-47b4-bc9f-bf36f486a088";
  const { accessToken } = await getAccessToken(userId);

  const response = await request(app)
    .get(`/api/v1/views/?userId=${userId}&limit=1`)
    .set("Authorization", `Bearer ${accessToken}`);

  expect(response.status).toEqual(200);
  expect(response.headers["content-type"]).toMatch(/json/);

  const responseJson = JSON.parse(response.text);
  expect(responseJson.data.length).toEqual(1);

  expect(prismaMock.view.findMany).toBeCalledWith(
    expect.objectContaining({ take: 1 })
  );
});

test("test views selfMitigation filtering", async () => {
  prismaMock.view.findMany.mockResolvedValue([
    mockViewNoSelfMitigationBad,
    mockViewNoSelfMitigationGood,
  ]);

  const userId = "71cf7000-cf96-47b4-bc9f-bf36f486a088";
  const { accessToken } = await getAccessToken(userId);

  const response = await request(app)
    .get(`/api/v1/views/?userId=${userId}&limit=1`)
    .set("Authorization", `Bearer ${accessToken}`);

  expect(response.status).toEqual(200);
  expect(response.headers["content-type"]).toMatch(/json/);

  const responseJson = JSON.parse(response.text);
  expect(responseJson.data.length).toEqual(1);

  expect(prismaMock.view.findMany).toBeCalledWith(
    expect.objectContaining({ take: 1 })
  );
});
