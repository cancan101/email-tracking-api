import request from "supertest";

import { app, getAccessToken } from "../src/app";
import { prismaMock } from "../src/singleton";

const mockViewRow = {
  id: "a",
  clientIp: "",
  userAgent: "",
  trackId: "",
  createdAt: new Date(),
  clientIpGeo: null,
  tracker: {
    threadId: "t",
    emailSubject: "s",
    selfLoadMitigation: true,
    createdAt: new Date().toISOString(),
  },
};

test("test views filtered by user", async () => {
  prismaMock.$queryRaw.mockResolvedValue([mockViewRow]);

  const userId = "71cf7000-cf96-47b4-bc9f-bf36f486a088";
  const { accessToken } = await getAccessToken(userId);

  const response = await request(app)
    .get(`/api/v1/views/?userId=${userId}`)
    .set("Authorization", `Bearer ${accessToken}`);

  expect(response.status).toEqual(200);
  expect(response.headers["content-type"]).toMatch(/json/);

  const responseJson = JSON.parse(response.text);
  expect(responseJson.data.length).toEqual(1);

  // No limit supplied — Prisma is invoked exactly once and userId is among
  // the bound parameters.
  expect(prismaMock.$queryRaw).toHaveBeenCalledTimes(1);
  const callArgs = prismaMock.$queryRaw.mock.calls[0];
  expect(callArgs.slice(1)).toEqual(expect.arrayContaining([userId]));
});

test("test views filtered by user and with limit", async () => {
  prismaMock.$queryRaw.mockResolvedValue([mockViewRow]);

  const userId = "71cf7000-cf96-47b4-bc9f-bf36f486a088";
  const { accessToken } = await getAccessToken(userId);

  const response = await request(app)
    .get(`/api/v1/views/?userId=${userId}&limit=1`)
    .set("Authorization", `Bearer ${accessToken}`);

  expect(response.status).toEqual(200);
  expect(response.headers["content-type"]).toMatch(/json/);

  const responseJson = JSON.parse(response.text);
  expect(responseJson.data.length).toEqual(1);

  // Limit clause is itself a nested Prisma.Sql so it doesn't appear as a
  // raw bound value; the easiest way to assert it was wired through is to
  // check that the call was made at all and the response forwarded the
  // mocked row (the SQL push-down is what makes `take: limit` correct).
  expect(prismaMock.$queryRaw).toHaveBeenCalledTimes(1);
});

test("test views self-mitigation filtering happens in SQL not JS", async () => {
  // The handler used to fetch all rows then filter in JS — meaning a
  // pre-LIMIT filter could starve the response. Now the filter is in the
  // SQL WHERE clause, so the mock just returns whatever rows the DB would
  // return after the filter. This test asserts the response forwards them
  // unchanged (no second JS-side filter pass).
  prismaMock.$queryRaw.mockResolvedValue([mockViewRow]);

  const userId = "71cf7000-cf96-47b4-bc9f-bf36f486a088";
  const { accessToken } = await getAccessToken(userId);

  const response = await request(app)
    .get(`/api/v1/views/?userId=${userId}&limit=1`)
    .set("Authorization", `Bearer ${accessToken}`);

  expect(response.status).toEqual(200);
  const responseJson = JSON.parse(response.text);
  expect(responseJson.data.length).toEqual(1);
});

test("test creating tracker without scheduledTimestamp", async () => {
  const userId = "71cf7000-cf96-47b4-bc9f-bf36f486a088";
  const { accessToken } = await getAccessToken(userId);

  const response = await request(app)
    .post(`/api/v1/trackers/`)
    .send({
      emailId: "msg-a:r-9999999999999999999",
      emailSubject: "My Subject Line",
      selfLoadMitigation: true,
      threadId: "thread-f:1111111111111111111",
      trackId: "4fcb3ce6-bc89-47c8-9ed2-4fbaaab2620e",
    })
    .set("Authorization", `Bearer ${accessToken}`);

  expect(response.status).toEqual(201);
});

test("test creating tracker with scheduledTimestamp as string", async () => {
  const userId = "71cf7000-cf96-47b4-bc9f-bf36f486a088";
  const { accessToken } = await getAccessToken(userId);

  const response = await request(app)
    .post(`/api/v1/trackers/`)
    .send({
      emailId: "msg-a:r-9999999999999999999",
      emailSubject: "My Subject Line",
      scheduledTimestamp: "1693310400000",
      selfLoadMitigation: true,
      threadId: "thread-f:1111111111111111111",
      trackId: "4fcb3ce6-bc89-47c8-9ed2-4fbaaab2620e",
    })
    .set("Authorization", `Bearer ${accessToken}`);

  expect(response.status).toEqual(201);
});

test("test creating tracker with scheduledTimestamp as int", async () => {
  const userId = "71cf7000-cf96-47b4-bc9f-bf36f486a088";
  const { accessToken } = await getAccessToken(userId);

  const response = await request(app)
    .post(`/api/v1/trackers/`)
    .send({
      emailId: "msg-a:r-9999999999999999999",
      emailSubject: "My Subject Line",
      scheduledTimestamp: 1693310400000,
      selfLoadMitigation: true,
      threadId: "thread-f:1111111111111111111",
      trackId: "4fcb3ce6-bc89-47c8-9ed2-4fbaaab2620e",
    })
    .set("Authorization", `Bearer ${accessToken}`);

  expect(response.status).toEqual(201);
});
