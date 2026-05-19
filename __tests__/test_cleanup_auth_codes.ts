import { cleanupAuthCodes } from "../scripts/cleanup_auth_codes";

jest.mock("@prisma/client", () => {
  const deleteMany = jest.fn();
  return {
    __esModule: true,
    PrismaClient: jest.fn().mockImplementation(() => ({
      authorizationCode: { deleteMany },
      $disconnect: jest.fn(),
    })),
    __deleteMany: deleteMany,
  };
});

// eslint-disable-next-line @typescript-eslint/no-var-requires
const { __deleteMany: deleteMany } = require("@prisma/client") as {
  __deleteMany: jest.Mock;
};

beforeEach(() => deleteMany.mockReset());

describe("cleanupAuthCodes", () => {
  test("deletes codes whose expiresAt is older than now - graceHours", async () => {
    deleteMany.mockResolvedValue({ count: 7 });

    const before = Date.now();
    const deleted = await cleanupAuthCodes(24);
    const after = Date.now();

    expect(deleted).toEqual(7);
    expect(deleteMany).toHaveBeenCalledTimes(1);
    const call = deleteMany.mock.calls[0][0];
    const cutoff: Date = call.where.expiresAt.lt;
    // Cutoff is now - 24h, evaluated at call time.
    const lowerBound = before - 24 * 60 * 60 * 1000;
    const upperBound = after - 24 * 60 * 60 * 1000;
    expect(cutoff.getTime()).toBeGreaterThanOrEqual(lowerBound);
    expect(cutoff.getTime()).toBeLessThanOrEqual(upperBound);
  });

  test("propagates errors from Prisma so the script exits non-zero", async () => {
    deleteMany.mockRejectedValue(new Error("connection lost"));
    await expect(cleanupAuthCodes(1)).rejects.toThrow(/connection lost/);
  });
});
