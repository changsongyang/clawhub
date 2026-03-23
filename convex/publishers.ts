import { getAuthUserId } from "@convex-dev/auth/server";
import { ConvexError, v } from "convex/values";
import type { Doc } from "./_generated/dataModel";
import { internalMutation, internalQuery, mutation, query } from "./functions";
import { assertAdmin, requireUser } from "./lib/access";
import {
  ensurePersonalPublisherForUser,
  getPublisherByHandle,
  getPublisherMembership,
  getPersonalPublisherForUser,
  isPublisherRoleAllowed,
  normalizePublisherHandle,
} from "./lib/publishers";
import { toPublicPublisher } from "./lib/public";

const PUBLISHER_HANDLE_PATTERN = /^[a-z0-9](?:[a-z0-9-]{0,38}[a-z0-9])?$/;

function validateHandle(rawHandle: string) {
  const handle = normalizePublisherHandle(rawHandle);
  if (!handle) throw new ConvexError("Handle is required");
  if (!PUBLISHER_HANDLE_PATTERN.test(handle)) {
    throw new ConvexError("Handle must be lowercase, url-safe, and 2-40 characters");
  }
  return handle;
}

export const getByIdInternal = internalQuery({
  args: { publisherId: v.id("publishers") },
  handler: async (ctx, args) => await ctx.db.get(args.publisherId),
});

export const getByHandleInternal = internalQuery({
  args: { handle: v.string() },
  handler: async (ctx, args) => await getPublisherByHandle(ctx, args.handle),
});

export const getMemberRoleInternal = internalQuery({
  args: {
    publisherId: v.id("publishers"),
    userId: v.id("users"),
  },
  handler: async (ctx, args) =>
    (await getPublisherMembership(ctx, args.publisherId, args.userId))?.role ?? null,
});

export const ensurePersonalPublisherInternal = internalMutation({
  args: { userId: v.id("users") },
  handler: async (ctx, args) => {
    const user = await ctx.db.get(args.userId);
    if (!user || user.deletedAt || user.deactivatedAt) return null;
    return await ensurePersonalPublisherForUser(ctx, user);
  },
});

export const resolvePublishTargetForUserInternal = internalQuery({
  args: {
    actorUserId: v.id("users"),
    ownerHandle: v.optional(v.string()),
    minimumRole: v.optional(v.union(v.literal("owner"), v.literal("admin"), v.literal("publisher"))),
  },
  handler: async (ctx, args) => {
    const actor = await ctx.db.get(args.actorUserId);
    if (!actor || actor.deletedAt || actor.deactivatedAt) throw new ConvexError("Unauthorized");
    const minimumRole = args.minimumRole ?? "publisher";
    const requestedHandle = normalizePublisherHandle(args.ownerHandle);
    const personal =
      actor.personalPublisherId
        ? await ctx.db.get(actor.personalPublisherId)
        : await getPersonalPublisherForUser(ctx, actor._id);
    if (!requestedHandle) {
      if (!personal || personal.deletedAt || personal.deactivatedAt) {
        throw new ConvexError("Personal publisher not found");
      }
      return {
        publisherId: personal._id,
        handle: personal.handle,
        kind: personal.kind,
        linkedUserId: personal.linkedUserId,
      };
    }

    if (personal && requestedHandle === personal.handle) {
      return {
        publisherId: personal._id,
        handle: personal.handle,
        kind: personal.kind,
        linkedUserId: personal.linkedUserId,
      };
    }

    const publisher = await getPublisherByHandle(ctx, requestedHandle);
    if (!publisher || publisher.deletedAt || publisher.deactivatedAt) {
      throw new ConvexError(`Publisher "@${requestedHandle}" not found`);
    }
    const membership = await getPublisherMembership(ctx, publisher._id, actor._id);
    if (!membership || !isPublisherRoleAllowed(membership.role, [minimumRole])) {
      throw new ConvexError(`Forbidden for "@${requestedHandle}"`);
    }
    return {
      publisherId: publisher._id,
      handle: publisher.handle,
      kind: publisher.kind,
      linkedUserId: publisher.linkedUserId,
    };
  },
});

export const listMine = query({
  args: {},
  handler: async (ctx) => {
    const userId = await getAuthUserId(ctx);
    if (!userId) return [];
    const memberships = await ctx.db
      .query("publisherMembers")
      .withIndex("by_user", (q) => q.eq("userId", userId))
      .collect();
    const publishers = await Promise.all(
      memberships.map(async (membership) => {
        const publisher = await ctx.db.get(membership.publisherId);
        const publicPublisher = toPublicPublisher(publisher);
        if (!publicPublisher) return null;
        return {
          publisher: publicPublisher,
          role: membership.role,
        };
      }),
    );
    return publishers.filter(
      (
        item,
      ): item is {
        publisher: NonNullable<ReturnType<typeof toPublicPublisher>>;
        role: Doc<"publisherMembers">["role"];
      } => Boolean(item),
    );
  },
});

export const getByHandle = query({
  args: { handle: v.string() },
  handler: async (ctx, args) => toPublicPublisher(await getPublisherByHandle(ctx, args.handle)),
});

export const listMembers = query({
  args: { publisherHandle: v.string() },
  handler: async (ctx, args) => {
    const publisher = await getPublisherByHandle(ctx, args.publisherHandle);
    if (!publisher || publisher.deletedAt || publisher.deactivatedAt) return null;
    const memberships = await ctx.db
      .query("publisherMembers")
      .withIndex("by_publisher", (q) => q.eq("publisherId", publisher._id))
      .collect();
    const items = await Promise.all(
      memberships.map(async (membership) => {
        const user = await ctx.db.get(membership.userId);
        if (!user || user.deletedAt || user.deactivatedAt) return null;
        return {
          role: membership.role,
          user: {
            _id: user._id,
            handle: user.handle ?? null,
            displayName: user.displayName ?? user.name ?? null,
            image: user.image ?? null,
          },
        };
      }),
    );
    return {
      publisher: toPublicPublisher(publisher),
      members: items.filter(Boolean),
    };
  },
});

export const createOrg = mutation({
  args: {
    handle: v.string(),
    displayName: v.string(),
    bio: v.optional(v.string()),
  },
  handler: async (ctx, args) => {
    const { user, userId } = await requireUser(ctx);
    await ensurePersonalPublisherForUser(ctx, user);

    const handle = validateHandle(args.handle);
    const existingPublisher = await getPublisherByHandle(ctx, handle);
    if (existingPublisher) throw new ConvexError(`Publisher "@${handle}" already exists`);

    const existingUser = await ctx.db
      .query("users")
      .withIndex("handle", (q) => q.eq("handle", handle))
      .unique();
    if (existingUser && existingUser._id !== userId) {
      throw new ConvexError(`Handle "@${handle}" is already claimed`);
    }

    const now = Date.now();
    const publisherId = await ctx.db.insert("publishers", {
      kind: "org",
      handle,
      displayName: args.displayName.trim() || handle,
      bio: args.bio?.trim() || undefined,
      image: undefined,
      linkedUserId: undefined,
      trustedPublisher: false,
      createdAt: now,
      updatedAt: now,
    });
    await ctx.db.insert("publisherMembers", {
      publisherId,
      userId,
      role: "owner",
      createdAt: now,
      updatedAt: now,
    });
    await ctx.db.insert("auditLogs", {
      actorUserId: userId,
      action: "publisher.create",
      targetType: "publisher",
      targetId: publisherId,
      metadata: { kind: "org", handle },
      createdAt: now,
    });
    return {
      publisher: toPublicPublisher(await ctx.db.get(publisherId)),
      role: "owner" as const,
    };
  },
});

export const addMember = mutation({
  args: {
    publisherId: v.id("publishers"),
    userHandle: v.string(),
    role: v.union(v.literal("owner"), v.literal("admin"), v.literal("publisher")),
  },
  handler: async (ctx, args) => {
    const { userId } = await requireUser(ctx);
    const publisher = await ctx.db.get(args.publisherId);
    if (!publisher || publisher.deletedAt || publisher.deactivatedAt) {
      throw new ConvexError("Publisher not found");
    }
    const membership = await getPublisherMembership(ctx, publisher._id, userId);
    if (!membership || !isPublisherRoleAllowed(membership.role, ["admin"])) {
      throw new ConvexError("Forbidden");
    }
    if (args.role === "owner" && membership.role !== "owner") {
      throw new ConvexError("Only org owners can promote members to owner");
    }
    const handle = normalizePublisherHandle(args.userHandle);
    if (!handle) throw new ConvexError("User handle is required");
    const targetUser = await ctx.db
      .query("users")
      .withIndex("handle", (q) => q.eq("handle", handle))
      .unique();
    if (!targetUser || targetUser.deletedAt || targetUser.deactivatedAt) {
      throw new ConvexError(`User "@${handle}" not found`);
    }
    await ensurePersonalPublisherForUser(ctx, targetUser);
    const existing = await getPublisherMembership(ctx, publisher._id, targetUser._id);
    const now = Date.now();
    if (existing) {
      await ctx.db.patch(existing._id, { role: args.role, updatedAt: now });
    } else {
      await ctx.db.insert("publisherMembers", {
        publisherId: publisher._id,
        userId: targetUser._id,
        role: args.role,
        createdAt: now,
        updatedAt: now,
      });
    }
    await ctx.db.insert("auditLogs", {
      actorUserId: userId,
      action: "publisher.member.upsert",
      targetType: "publisher",
      targetId: publisher._id,
      metadata: {
        memberUserId: targetUser._id,
        memberHandle: targetUser.handle ?? handle,
        role: args.role,
      },
      createdAt: now,
    });
    return { ok: true };
  },
});

export const removeMember = mutation({
  args: {
    publisherId: v.id("publishers"),
    userId: v.id("users"),
  },
  handler: async (ctx, args) => {
    const { userId } = await requireUser(ctx);
    const publisher = await ctx.db.get(args.publisherId);
    if (!publisher || publisher.deletedAt || publisher.deactivatedAt) {
      throw new ConvexError("Publisher not found");
    }
    const actorMembership = await getPublisherMembership(ctx, publisher._id, userId);
    if (!actorMembership || !isPublisherRoleAllowed(actorMembership.role, ["admin"])) {
      throw new ConvexError("Forbidden");
    }
    const targetMembership = await getPublisherMembership(ctx, publisher._id, args.userId);
    if (!targetMembership) return { ok: true };
    if (targetMembership.role === "owner" && actorMembership.role !== "owner") {
      throw new ConvexError("Only org owners can remove other owners");
    }
    if (targetMembership.role === "owner") {
      const members = await ctx.db
        .query("publisherMembers")
        .withIndex("by_publisher", (q) => q.eq("publisherId", publisher._id))
        .collect();
      const remainingOwners = members.filter(
        (member) => member.role === "owner" && member.userId !== args.userId,
      );
      if (remainingOwners.length === 0) {
        throw new ConvexError("Publisher must have at least one owner");
      }
    }
    await ctx.db.delete(targetMembership._id);
    await ctx.db.insert("auditLogs", {
      actorUserId: userId,
      action: "publisher.member.remove",
      targetType: "publisher",
      targetId: publisher._id,
      metadata: { memberUserId: args.userId },
      createdAt: Date.now(),
    });
    return { ok: true };
  },
});

export const setTrustedPublisherInternal = internalMutation({
  args: {
    actorUserId: v.id("users"),
    publisherId: v.id("publishers"),
    trustedPublisher: v.boolean(),
  },
  handler: async (ctx, args) => {
    const actor = await ctx.db.get(args.actorUserId);
    if (!actor || actor.deletedAt || actor.deactivatedAt) throw new ConvexError("Unauthorized");
    assertAdmin(actor);
    await ctx.db.patch(args.publisherId, {
      trustedPublisher: args.trustedPublisher,
      updatedAt: Date.now(),
    });
  },
});
