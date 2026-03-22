/* @vitest-environment node */

import { describe, expect, it, vi } from "vitest";
import {
  repointPackageLatestRelease,
  syncPackageSearchDigestForPackageId,
  syncPackageSearchDigestsForOwnerUserId,
} from "./functions";

describe("package digest sync", () => {
  it("clears latestVersion when the current package release is soft-deleted", async () => {
    const pkg = {
      _id: "packages:demo",
      name: "demo-plugin",
      normalizedName: "demo-plugin",
      displayName: "Demo Plugin",
      family: "code-plugin",
      channel: "community",
      isOfficial: false,
      ownerUserId: "users:owner",
      summary: "demo",
      capabilityTags: ["tools"],
      executesCode: true,
      runtimeId: null,
      softDeletedAt: undefined,
      createdAt: 1,
      updatedAt: 2,
      latestReleaseId: "packageReleases:demo-2",
      latestVersionSummary: { version: "2.0.0" },
      verification: { tier: "community" },
    };
    const latestRelease = {
      _id: "packageReleases:demo-2",
      version: "2.0.0",
      softDeletedAt: 10,
    };
    const owner = {
      _id: "users:owner",
      handle: "owner",
      deletedAt: undefined,
      deactivatedAt: undefined,
    };
    const ctx = {
      db: {
        get: vi.fn(async (id: string) => {
          if (id === "packages:demo") return pkg;
          if (id === "packageReleases:demo-2") return latestRelease;
          if (id === "users:owner") return owner;
          return null;
        }),
        query: vi.fn(() => ({
          withIndex: vi.fn(() => ({
            unique: vi.fn().mockResolvedValue(null),
          })),
        })),
        patch: vi.fn(),
        insert: vi.fn(),
        delete: vi.fn(),
      },
    };

    await syncPackageSearchDigestForPackageId(
      ctx as never,
      "packages:demo" as never,
    );

    expect(ctx.db.insert).toHaveBeenCalledWith(
      "packageSearchDigest",
      expect.objectContaining({
        packageId: "packages:demo",
        latestVersion: undefined,
        ownerHandle: "owner",
      }),
    );
  });

  it("repoints packages to the highest-version active release and restores its summary", async () => {
    const pkg = {
      _id: "packages:demo",
      _creationTime: 1,
      name: "demo-plugin",
      normalizedName: "demo-plugin",
      displayName: "Demo Plugin",
      family: "code-plugin",
      channel: "community",
      isOfficial: false,
      ownerUserId: "users:owner",
      summary: "latest summary",
      tags: {
        latest: "packageReleases:demo-2",
        stable: "packageReleases:demo-2",
      },
      latestReleaseId: "packageReleases:demo-2",
      latestVersionSummary: { version: "2.0.0" },
      capabilityTags: ["new"],
      executesCode: true,
      compatibility: { openclaw: "^2.0.0" },
      capabilities: { capabilityTags: ["new"], executesCode: true },
      verification: { tier: "community" },
      runtimeId: null,
      softDeletedAt: undefined,
      createdAt: 1,
      updatedAt: 2,
    };
    const fallbackRelease = {
      _id: "packageReleases:demo-1",
      _creationTime: 10,
      packageId: "packages:demo",
      version: "1.0.0",
      changelog: "old stable",
      summary: "stable summary",
      compatibility: { openclaw: "^1.0.0" },
      capabilities: { capabilityTags: ["stable"], executesCode: false },
      verification: { tier: "verified" },
      distTags: ["stable"],
      createdAt: 10,
      softDeletedAt: undefined,
    };
    const legacyHotfixRelease = {
      _id: "packageReleases:demo-legacy",
      _creationTime: 20,
      packageId: "packages:demo",
      version: "0.9.9",
      changelog: "legacy hotfix",
      summary: "legacy summary",
      compatibility: { openclaw: "^0.9.0" },
      capabilities: { capabilityTags: ["legacy"], executesCode: false },
      verification: { tier: "verified" },
      distTags: ["legacy"],
      createdAt: 20,
      softDeletedAt: undefined,
    };
    const owner = {
      _id: "users:owner",
      handle: "owner",
      deletedAt: undefined,
      deactivatedAt: undefined,
    };
    const ctx = {
      db: {
        get: vi.fn(async (id: string) => {
          if (id === "packages:demo") return pkg;
          if (id === "packageReleases:demo-1") return fallbackRelease;
          if (id === "users:owner") return owner;
          return null;
        }),
        query: vi.fn((table: string) => {
          if (table === "packageReleases") {
            return {
              withIndex: vi.fn(() => ({
                order: vi.fn(() => ({
                  paginate: vi.fn().mockResolvedValue({
                    page: [legacyHotfixRelease, fallbackRelease],
                    isDone: true,
                    continueCursor: "",
                  }),
                })),
              })),
            };
          }
          if (table === "packageSearchDigest") {
            return {
              withIndex: vi.fn(() => ({
                unique: vi.fn().mockResolvedValue(null),
              })),
            };
          }
          throw new Error(`Unexpected table ${table}`);
        }),
        patch: vi.fn(),
        insert: vi.fn(),
        delete: vi.fn(),
      },
    };

    await repointPackageLatestRelease(
      ctx as never,
      "packages:demo" as never,
      "packageReleases:demo-2" as never,
    );

    expect(ctx.db.patch).toHaveBeenCalledWith("packageReleases:demo-1", {
      distTags: ["stable", "latest"],
    });
    expect(ctx.db.patch).toHaveBeenCalledWith(
      "packages:demo",
      expect.objectContaining({
        latestReleaseId: "packageReleases:demo-1",
        tags: { latest: "packageReleases:demo-1" },
        latestVersionSummary: expect.objectContaining({ version: "1.0.0" }),
        summary: "stable summary",
        capabilityTags: ["stable"],
        executesCode: false,
      }),
    );
    expect(ctx.db.insert).toHaveBeenCalledWith(
      "packageSearchDigest",
      expect.objectContaining({
        latestVersion: "1.0.0",
        ownerHandle: "owner",
      }),
    );
  });

  it("re-syncs package digests when an owner handle changes", async () => {
    const owner = {
      _id: "users:owner",
      handle: "renamed",
      deletedAt: undefined,
      deactivatedAt: undefined,
    };
    const pkg = {
      _id: "packages:demo",
      _creationTime: 1,
      name: "demo-plugin",
      normalizedName: "demo-plugin",
      displayName: "Demo Plugin",
      family: "code-plugin",
      channel: "community",
      isOfficial: false,
      ownerUserId: "users:owner",
      summary: "demo",
      tags: {},
      latestReleaseId: undefined,
      latestVersionSummary: undefined,
      capabilityTags: [],
      executesCode: false,
      runtimeId: null,
      softDeletedAt: undefined,
      createdAt: 1,
      updatedAt: 2,
      verification: undefined,
    };
    const paginate = vi
      .fn()
      .mockResolvedValueOnce({
        page: [pkg],
        isDone: true,
        continueCursor: "",
      });
    const ctx = {
      db: {
        get: vi.fn(async (id: string) => {
          if (id === "users:owner") return owner;
          return null;
        }),
        query: vi.fn((table: string) => {
          if (table === "packages") {
            return {
              withIndex: vi.fn(() => ({
                paginate,
              })),
            };
          }
          if (table === "packageSearchDigest") {
            return {
              withIndex: vi.fn(() => ({
                unique: vi.fn().mockResolvedValue(null),
              })),
            };
          }
          throw new Error(`Unexpected table ${table}`);
        }),
        patch: vi.fn(),
        insert: vi.fn(),
        delete: vi.fn(),
      },
    };

    await syncPackageSearchDigestsForOwnerUserId(
      ctx as never,
      "users:owner" as never,
    );

    expect(paginate).toHaveBeenCalledWith({ cursor: null, numItems: 100 });
    expect(ctx.db.insert).toHaveBeenCalledWith(
      "packageSearchDigest",
      expect.objectContaining({
        packageId: "packages:demo",
        ownerHandle: "renamed",
      }),
    );
  });
});
