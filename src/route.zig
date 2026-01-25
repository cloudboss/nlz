//! Route message structures and attributes.
//!
//! This module handles parsing and building of RTM_*ROUTE messages used for
//! querying and configuring routing table entries.

const std = @import("std");
const mem = std.mem;
const message = @import("message.zig");
const rtnetlink = @import("rtnetlink.zig");

/// Route message header (struct rtmsg).
///
/// This structure follows the netlink header in route messages.
pub const RtMsg = extern struct {
    /// Address family (AF_INET or AF_INET6).
    family: u8,
    /// Destination prefix length.
    dst_len: u8,
    /// Source prefix length.
    src_len: u8,
    /// Type of service.
    tos: u8,
    /// Routing table ID.
    table: u8,
    /// Routing protocol (RTPROT_*).
    protocol: u8,
    /// Route scope (RT_SCOPE_*).
    scope: u8,
    /// Route type (RTN_*).
    type: u8,
    /// Route flags.
    flags: u32,

    pub const SIZE: usize = 12;

    comptime {
        std.debug.assert(@sizeOf(RtMsg) == SIZE);
    }

    /// Parse from raw bytes.
    pub fn fromBytes(bytes: []const u8) ?RtMsg {
        if (bytes.len < SIZE) return null;
        return mem.bytesAsValue(RtMsg, bytes[0..SIZE]).*;
    }

    /// Get raw bytes.
    pub fn toBytes(self: *const RtMsg) *const [SIZE]u8 {
        return @ptrCast(self);
    }
};

/// Route attribute types (RTA_*).
pub const Attr = struct {
    pub const UNSPEC: u16 = 0;
    /// Destination address.
    pub const DST: u16 = 1;
    /// Source address.
    pub const SRC: u16 = 2;
    /// Input interface index.
    pub const IIF: u16 = 3;
    /// Output interface index.
    pub const OIF: u16 = 4;
    /// Gateway address.
    pub const GATEWAY: u16 = 5;
    /// Route priority/metric.
    pub const PRIORITY: u16 = 6;
    /// Preferred source address.
    pub const PREFSRC: u16 = 7;
    /// Route metrics.
    pub const METRICS: u16 = 8;
    /// Multipath next hops.
    pub const MULTIPATH: u16 = 9;
    /// Protocol info.
    pub const PROTOINFO: u16 = 10;
    /// Flow classifier.
    pub const FLOW: u16 = 11;
    /// Cache info.
    pub const CACHEINFO: u16 = 12;
    pub const SESSION: u16 = 13;
    pub const MP_ALGO: u16 = 14;
    /// Extended routing table ID.
    pub const TABLE: u16 = 15;
    /// Firewall mark.
    pub const MARK: u16 = 16;
    pub const MFC_STATS: u16 = 17;
    /// Via address.
    pub const VIA: u16 = 18;
    /// New destination for MPLS.
    pub const NEWDST: u16 = 19;
    /// IPv6 route preference.
    pub const PREF: u16 = 20;
    /// Encapsulation type.
    pub const ENCAP_TYPE: u16 = 21;
    /// Encapsulation data.
    pub const ENCAP: u16 = 22;
    /// Route expiration time.
    pub const EXPIRES: u16 = 23;
};

/// Route flags (RTM_F_*).
pub const RouteFlags = struct {
    /// Notify user of route change.
    pub const NOTIFY: u32 = 0x100;
    /// This route is cloned.
    pub const CLONED: u32 = 0x200;
    /// Multipath equalizer.
    pub const EQUALIZE: u32 = 0x400;
    /// Prefix addresses.
    pub const PREFIX: u32 = 0x800;
    /// Use lookup table.
    pub const LOOKUP_TABLE: u32 = 0x1000;
    /// Match FIB entry.
    pub const FIB_MATCH: u32 = 0x2000;
};

/// Parsed route message.
///
/// Contains the route header and optional attributes like destination,
/// gateway, and output interface.
pub const RouteMessage = struct {
    /// The route message header.
    header: RtMsg,
    /// Destination address.
    dst: ?[]const u8 = null,
    /// Source address.
    src: ?[]const u8 = null,
    /// Gateway address.
    gateway: ?[]const u8 = null,
    /// Output interface index.
    oif: ?u32 = null,
    /// Input interface index.
    iif: ?u32 = null,
    /// Route priority/metric.
    priority: ?u32 = null,
    /// Extended routing table ID.
    table: ?u32 = null,

    /// Parse a route message from payload bytes (after netlink header).
    pub fn parse(payload: []const u8) ?RouteMessage {
        const header = RtMsg.fromBytes(payload) orelse return null;
        var result = RouteMessage{ .header = header };

        var iter = message.AttributeIterator.init(payload[RtMsg.SIZE..]);
        while (iter.next()) |item| {
            const attr_type = item.attr.type & 0x7fff;
            switch (attr_type) {
                Attr.DST => {
                    result.dst = item.attr.payload(item.data);
                },
                Attr.SRC => {
                    result.src = item.attr.payload(item.data);
                },
                Attr.GATEWAY => {
                    result.gateway = item.attr.payload(item.data);
                },
                Attr.OIF => {
                    result.oif = item.attr.payloadAs(u32, item.data);
                },
                Attr.IIF => {
                    result.iif = item.attr.payloadAs(u32, item.data);
                },
                Attr.PRIORITY => {
                    result.priority = item.attr.payloadAs(u32, item.data);
                },
                Attr.TABLE => {
                    result.table = item.attr.payloadAs(u32, item.data);
                },
                else => {},
            }
        }
        return result;
    }

    /// Get the address family.
    pub fn family(self: RouteMessage) u8 {
        return self.header.family;
    }

    /// Get the destination prefix length.
    pub fn dstLen(self: RouteMessage) u8 {
        return self.header.dst_len;
    }

    /// Check if this is an IPv4 route.
    pub fn isIPv4(self: RouteMessage) bool {
        return self.header.family == rtnetlink.AF.INET;
    }

    /// Check if this is an IPv6 route.
    pub fn isIPv6(self: RouteMessage) bool {
        return self.header.family == rtnetlink.AF.INET6;
    }

    /// Check if this is a default route (0.0.0.0/0 or ::/0).
    pub fn isDefaultRoute(self: RouteMessage) bool {
        return self.header.dst_len == 0;
    }

    /// Get the IPv4 destination as a 4-byte array.
    pub fn getIPv4Dst(self: RouteMessage) ?[4]u8 {
        if (!self.isIPv4()) return null;
        const dst = self.dst orelse return null;
        if (dst.len < 4) return null;
        return dst[0..4].*;
    }

    /// Get the IPv4 gateway as a 4-byte array.
    pub fn getIPv4Gateway(self: RouteMessage) ?[4]u8 {
        if (!self.isIPv4()) return null;
        const gw = self.gateway orelse return null;
        if (gw.len < 4) return null;
        return gw[0..4].*;
    }

    /// Get the IPv6 destination as a 16-byte array.
    pub fn getIPv6Dst(self: RouteMessage) ?[16]u8 {
        if (!self.isIPv6()) return null;
        const dst = self.dst orelse return null;
        if (dst.len < 16) return null;
        return dst[0..16].*;
    }

    /// Get the IPv6 gateway as a 16-byte array.
    pub fn getIPv6Gateway(self: RouteMessage) ?[16]u8 {
        if (!self.isIPv6()) return null;
        const gw = self.gateway orelse return null;
        if (gw.len < 16) return null;
        return gw[0..16].*;
    }
};

/// Builder for route messages.
pub const RouteMessageBuilder = struct {
    buffer: [4096]u8 = undefined,
    len: usize = 0,

    /// Create a new empty builder.
    pub fn init() RouteMessageBuilder {
        return .{};
    }

    /// Create a RTM_NEWROUTE request for an IPv4 route.
    pub fn newRouteIPv4(dst: [4]u8, prefix_len: u8, ifindex: u32) RouteMessageBuilder {
        var builder = RouteMessageBuilder.init();
        builder.addHeader(rtnetlink.Type.NEWROUTE, message.Flags.REQUEST | message.Flags.ACK | message.Flags.CREATE | message.Flags.EXCL);
        builder.addRtMsg(.{
            .family = rtnetlink.AF.INET,
            .dst_len = prefix_len,
            .src_len = 0,
            .tos = 0,
            .table = rtnetlink.RT_TABLE.MAIN,
            .protocol = rtnetlink.RTPROT.BOOT,
            .scope = rtnetlink.RT_SCOPE.UNIVERSE,
            .type = rtnetlink.RTN.UNICAST,
            .flags = 0,
        });
        if (prefix_len > 0) {
            builder.addAttrBytes(Attr.DST, &dst);
        }
        builder.addAttrU32(Attr.OIF, ifindex);
        return builder;
    }

    /// Create a RTM_NEWROUTE request for an IPv6 route.
    pub fn newRouteIPv6(dst: [16]u8, prefix_len: u8, ifindex: u32) RouteMessageBuilder {
        var builder = RouteMessageBuilder.init();
        builder.addHeader(rtnetlink.Type.NEWROUTE, message.Flags.REQUEST | message.Flags.ACK | message.Flags.CREATE | message.Flags.EXCL);
        builder.addRtMsg(.{
            .family = rtnetlink.AF.INET6,
            .dst_len = prefix_len,
            .src_len = 0,
            .tos = 0,
            .table = rtnetlink.RT_TABLE.MAIN,
            .protocol = rtnetlink.RTPROT.BOOT,
            .scope = rtnetlink.RT_SCOPE.UNIVERSE,
            .type = rtnetlink.RTN.UNICAST,
            .flags = 0,
        });
        if (prefix_len > 0) {
            builder.addAttrBytes(Attr.DST, &dst);
        }
        builder.addAttrU32(Attr.OIF, ifindex);
        return builder;
    }

    /// Create a RTM_DELROUTE request for an IPv4 route.
    pub fn delRouteIPv4(dst: [4]u8, prefix_len: u8, ifindex: u32) RouteMessageBuilder {
        var builder = RouteMessageBuilder.init();
        builder.addHeader(rtnetlink.Type.DELROUTE, message.Flags.REQUEST | message.Flags.ACK);
        builder.addRtMsg(.{
            .family = rtnetlink.AF.INET,
            .dst_len = prefix_len,
            .src_len = 0,
            .tos = 0,
            .table = rtnetlink.RT_TABLE.MAIN,
            .protocol = 0,
            .scope = rtnetlink.RT_SCOPE.UNIVERSE,
            .type = rtnetlink.RTN.UNICAST,
            .flags = 0,
        });
        if (prefix_len > 0) {
            builder.addAttrBytes(Attr.DST, &dst);
        }
        builder.addAttrU32(Attr.OIF, ifindex);
        return builder;
    }

    /// Create a RTM_DELROUTE request for an IPv6 route.
    pub fn delRouteIPv6(dst: [16]u8, prefix_len: u8, ifindex: u32) RouteMessageBuilder {
        var builder = RouteMessageBuilder.init();
        builder.addHeader(rtnetlink.Type.DELROUTE, message.Flags.REQUEST | message.Flags.ACK);
        builder.addRtMsg(.{
            .family = rtnetlink.AF.INET6,
            .dst_len = prefix_len,
            .src_len = 0,
            .tos = 0,
            .table = rtnetlink.RT_TABLE.MAIN,
            .protocol = 0,
            .scope = rtnetlink.RT_SCOPE.UNIVERSE,
            .type = rtnetlink.RTN.UNICAST,
            .flags = 0,
        });
        if (prefix_len > 0) {
            builder.addAttrBytes(Attr.DST, &dst);
        }
        builder.addAttrU32(Attr.OIF, ifindex);
        return builder;
    }

    /// Set the IPv4 gateway.
    pub fn setGatewayIPv4(self: *RouteMessageBuilder, gateway: [4]u8) *RouteMessageBuilder {
        self.addAttrBytes(Attr.GATEWAY, &gateway);
        return self;
    }

    /// Set the IPv6 gateway.
    pub fn setGatewayIPv6(self: *RouteMessageBuilder, gateway: [16]u8) *RouteMessageBuilder {
        self.addAttrBytes(Attr.GATEWAY, &gateway);
        return self;
    }

    fn addHeader(self: *RouteMessageBuilder, msg_type: u16, flags: u16) void {
        const header = message.Header{
            .len = 0,
            .type = msg_type,
            .flags = flags,
            .seq = 0,
            .pid = 0,
        };
        @memcpy(self.buffer[0..message.Header.SIZE], header.toBytes());
        self.len = message.Header.SIZE;
    }

    fn addRtMsg(self: *RouteMessageBuilder, info: RtMsg) void {
        @memcpy(self.buffer[self.len..][0..RtMsg.SIZE], info.toBytes());
        self.len += RtMsg.SIZE;
    }

    fn addAttrBytes(self: *RouteMessageBuilder, attr_type: u16, value: []const u8) void {
        const attr_len: u16 = @intCast(message.Attribute.HEADER_SIZE + value.len);
        const aligned_len = message.align4(attr_len);

        self.buffer[self.len] = @truncate(attr_len);
        self.buffer[self.len + 1] = @truncate(attr_len >> 8);
        self.buffer[self.len + 2] = @truncate(attr_type);
        self.buffer[self.len + 3] = @truncate(attr_type >> 8);
        self.len += message.Attribute.HEADER_SIZE;

        @memcpy(self.buffer[self.len..][0..value.len], value);
        const padding = aligned_len - message.Attribute.HEADER_SIZE - value.len;
        @memset(self.buffer[self.len + value.len ..][0..padding], 0);
        self.len += aligned_len - message.Attribute.HEADER_SIZE;
    }

    fn addAttrU32(self: *RouteMessageBuilder, attr_type: u16, value: u32) void {
        const bytes = mem.toBytes(value);
        self.addAttrBytes(attr_type, &bytes);
    }

    /// Build the final message bytes.
    pub fn build(self: *RouteMessageBuilder) []const u8 {
        const len: u32 = @intCast(self.len);
        self.buffer[0] = @truncate(len);
        self.buffer[1] = @truncate(len >> 8);
        self.buffer[2] = @truncate(len >> 16);
        self.buffer[3] = @truncate(len >> 24);
        return self.buffer[0..self.len];
    }
};

// =============================================================================
// Tests
// =============================================================================

test "rtmsg size" {
    try std.testing.expectEqual(@as(usize, 12), RtMsg.SIZE);
}

test "parse route message" {
    var payload: [32]u8 = undefined;
    @memset(&payload, 0);

    // RtMsg header
    payload[0] = rtnetlink.AF.INET; // family
    payload[1] = 0; // dst_len (default route)
    payload[4] = rtnetlink.RT_TABLE.MAIN; // table
    payload[5] = rtnetlink.RTPROT.DHCP; // protocol
    payload[6] = rtnetlink.RT_SCOPE.UNIVERSE; // scope
    payload[7] = rtnetlink.RTN.UNICAST; // type

    // RTA_GATEWAY attribute at offset 12
    payload[12] = 8; // len = 8 (4 header + 4 bytes)
    payload[14] = Attr.GATEWAY; // type
    payload[16] = 192;
    payload[17] = 168;
    payload[18] = 1;
    payload[19] = 1;

    // RTA_OIF attribute at offset 20
    payload[20] = 8; // len = 8
    payload[22] = Attr.OIF; // type
    payload[24] = 2; // ifindex = 2

    const route = RouteMessage.parse(&payload).?;
    try std.testing.expect(route.isDefaultRoute());
    try std.testing.expect(route.isIPv4());

    const gateway = route.getIPv4Gateway().?;
    try std.testing.expectEqual([_]u8{ 192, 168, 1, 1 }, gateway);
    try std.testing.expectEqual(@as(u32, 2), route.oif.?);
}

test "route message builder newRouteIPv4 default" {
    var builder = RouteMessageBuilder.newRouteIPv4(.{ 0, 0, 0, 0 }, 0, 2);
    _ = builder.setGatewayIPv4(.{ 10, 0, 0, 1 });
    const data = builder.build();

    const header = message.Header.fromBytes(data).?;
    try std.testing.expectEqual(@as(u16, rtnetlink.Type.NEWROUTE), header.type);

    const rtmsg = RtMsg.fromBytes(data[message.Header.SIZE..]).?;
    try std.testing.expectEqual(@as(u8, rtnetlink.AF.INET), rtmsg.family);
    try std.testing.expectEqual(@as(u8, 0), rtmsg.dst_len);
    try std.testing.expectEqual(@as(u8, rtnetlink.RT_TABLE.MAIN), rtmsg.table);
}

test "route message builder delRouteIPv4" {
    var builder = RouteMessageBuilder.delRouteIPv4(.{ 0, 0, 0, 0 }, 0, 3);
    const data = builder.build();

    const header = message.Header.fromBytes(data).?;
    try std.testing.expectEqual(@as(u16, rtnetlink.Type.DELROUTE), header.type);

    const rtmsg = RtMsg.fromBytes(data[message.Header.SIZE..]).?;
    try std.testing.expectEqual(@as(u8, 0), rtmsg.dst_len);
}

test "route message isDefaultRoute" {
    var route = RouteMessage{ .header = undefined };
    route.header.dst_len = 0;
    try std.testing.expect(route.isDefaultRoute());

    route.header.dst_len = 24;
    try std.testing.expect(!route.isDefaultRoute());
}

test "route message parse too short" {
    var payload: [8]u8 = undefined; // Need 12 bytes for RtMsg
    @memset(&payload, 0);

    try std.testing.expect(RouteMessage.parse(&payload) == null);
}

test "route message getIPv4Dst wrong family" {
    var payload: [16]u8 = undefined;
    @memset(&payload, 0);
    payload[0] = rtnetlink.AF.INET6;

    const route = RouteMessage.parse(&payload).?;
    try std.testing.expect(route.getIPv4Dst() == null);
    try std.testing.expect(route.getIPv4Gateway() == null);
}

test "route message getIPv6Dst wrong family" {
    var payload: [16]u8 = undefined;
    @memset(&payload, 0);
    payload[0] = rtnetlink.AF.INET;

    const route = RouteMessage.parse(&payload).?;
    try std.testing.expect(route.getIPv6Dst() == null);
    try std.testing.expect(route.getIPv6Gateway() == null);
}

test "route message getIPv4Dst no dst" {
    var payload: [16]u8 = undefined;
    @memset(&payload, 0);
    payload[0] = rtnetlink.AF.INET;

    const route = RouteMessage.parse(&payload).?;
    try std.testing.expect(route.getIPv4Dst() == null);
}

test "rtmsg toBytes roundtrip" {
    const info = RtMsg{
        .family = rtnetlink.AF.INET,
        .dst_len = 24,
        .src_len = 0,
        .tos = 0,
        .table = rtnetlink.RT_TABLE.MAIN,
        .protocol = rtnetlink.RTPROT.DHCP,
        .scope = rtnetlink.RT_SCOPE.UNIVERSE,
        .type = rtnetlink.RTN.UNICAST,
        .flags = 0,
    };

    const bytes = info.toBytes();
    const parsed = RtMsg.fromBytes(bytes).?;

    try std.testing.expectEqual(info.family, parsed.family);
    try std.testing.expectEqual(info.dst_len, parsed.dst_len);
    try std.testing.expectEqual(info.table, parsed.table);
    try std.testing.expectEqual(info.protocol, parsed.protocol);
    try std.testing.expectEqual(info.scope, parsed.scope);
    try std.testing.expectEqual(info.type, parsed.type);
}

test "route message builder newRouteIPv4 with prefix" {
    var builder = RouteMessageBuilder.newRouteIPv4(.{ 10, 0, 0, 0 }, 8, 2);
    _ = builder.setGatewayIPv4(.{ 192, 168, 1, 1 });
    const data = builder.build();

    const rtmsg = RtMsg.fromBytes(data[message.Header.SIZE..]).?;
    try std.testing.expectEqual(@as(u8, 8), rtmsg.dst_len);

    // With prefix > 0, DST attribute should be present
    // Find RTA_DST in attributes
    var iter = message.AttributeIterator.init(data[message.Header.SIZE + RtMsg.SIZE ..]);
    var found_dst = false;
    var found_gateway = false;
    while (iter.next()) |item| {
        if (item.attr.type == Attr.DST) {
            found_dst = true;
            const dst = item.attr.payload(item.data).?;
            try std.testing.expectEqual([_]u8{ 10, 0, 0, 0 }, dst[0..4].*);
        }
        if (item.attr.type == Attr.GATEWAY) {
            found_gateway = true;
        }
    }
    try std.testing.expect(found_dst);
    try std.testing.expect(found_gateway);
}

test "route message builder newRouteIPv6" {
    var dst: [16]u8 = undefined;
    @memset(&dst, 0);
    dst[0] = 0x20;
    dst[1] = 0x01;

    var gw: [16]u8 = undefined;
    @memset(&gw, 0);
    gw[0] = 0xfe;
    gw[1] = 0x80;
    gw[15] = 0x01;

    var builder = RouteMessageBuilder.newRouteIPv6(dst, 64, 3);
    _ = builder.setGatewayIPv6(gw);
    const data = builder.build();

    const header = message.Header.fromBytes(data).?;
    try std.testing.expectEqual(@as(u16, rtnetlink.Type.NEWROUTE), header.type);

    const rtmsg = RtMsg.fromBytes(data[message.Header.SIZE..]).?;
    try std.testing.expectEqual(@as(u8, rtnetlink.AF.INET6), rtmsg.family);
    try std.testing.expectEqual(@as(u8, 64), rtmsg.dst_len);
}

test "route message builder delRouteIPv6" {
    var dst: [16]u8 = undefined;
    @memset(&dst, 0);

    var builder = RouteMessageBuilder.delRouteIPv6(dst, 0, 2);
    const data = builder.build();

    const header = message.Header.fromBytes(data).?;
    try std.testing.expectEqual(@as(u16, rtnetlink.Type.DELROUTE), header.type);
}

test "parse route message with priority" {
    var payload: [32]u8 = undefined;
    @memset(&payload, 0);

    payload[0] = rtnetlink.AF.INET;
    payload[4] = rtnetlink.RT_TABLE.MAIN;

    // RTA_PRIORITY at offset 12
    payload[12] = 8; // len = 8
    payload[14] = Attr.PRIORITY;
    payload[16] = 100; // priority = 100

    const route = RouteMessage.parse(&payload).?;
    try std.testing.expectEqual(@as(u32, 100), route.priority.?);
}

test "parse route message with table attribute" {
    var payload: [32]u8 = undefined;
    @memset(&payload, 0);

    payload[0] = rtnetlink.AF.INET;

    // RTA_TABLE at offset 12
    payload[12] = 8; // len = 8
    payload[14] = Attr.TABLE;
    payload[16] = 200; // table = 200

    const route = RouteMessage.parse(&payload).?;
    try std.testing.expectEqual(@as(u32, 200), route.table.?);
}

test "parse route message with iif" {
    var payload: [32]u8 = undefined;
    @memset(&payload, 0);

    payload[0] = rtnetlink.AF.INET;

    // RTA_IIF at offset 12
    payload[12] = 8;
    payload[14] = Attr.IIF;
    payload[16] = 5; // iif = 5

    const route = RouteMessage.parse(&payload).?;
    try std.testing.expectEqual(@as(u32, 5), route.iif.?);
}
