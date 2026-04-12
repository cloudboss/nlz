//! Link (network interface) message structures and attributes.
//!
//! This module handles parsing and building of RTM_*LINK messages used for
//! querying and configuring network interfaces.

const std = @import("std");
const mem = std.mem;
const message = @import("message.zig");
const rtnetlink = @import("rtnetlink.zig");

/// Interface info message header (struct ifinfomsg).
///
/// This structure follows the netlink header in link messages and contains
/// basic interface properties.
pub const IfInfoMsg = extern struct {
    /// Address family (usually AF_UNSPEC or AF_PACKET).
    family: u8,
    _pad: u8 = 0,
    /// Device type (ARPHRD_*).
    type: u16,
    /// Interface index.
    index: i32,
    /// Interface flags (IFF_*).
    flags: u32,
    /// Change mask for flags.
    change: u32,

    pub const SIZE: usize = 16;

    comptime {
        std.debug.assert(@sizeOf(IfInfoMsg) == SIZE);
    }

    /// Parse from raw bytes.
    pub fn fromBytes(bytes: []const u8) ?IfInfoMsg {
        if (bytes.len < SIZE) return null;
        return mem.bytesAsValue(IfInfoMsg, bytes[0..SIZE]).*;
    }

    /// Get raw bytes.
    pub fn toBytes(self: *const IfInfoMsg) *const [SIZE]u8 {
        return @ptrCast(self);
    }
};

/// Link attribute types (IFLA_*).
pub const Attr = struct {
    pub const UNSPEC: u16 = 0;
    /// Hardware address (MAC).
    pub const ADDRESS: u16 = 1;
    /// Broadcast address.
    pub const BROADCAST: u16 = 2;
    /// Interface name.
    pub const IFNAME: u16 = 3;
    /// MTU of device.
    pub const MTU: u16 = 4;
    /// Link type.
    pub const LINK: u16 = 5;
    /// Queueing discipline.
    pub const QDISC: u16 = 6;
    /// Interface statistics.
    pub const STATS: u16 = 7;
    pub const COST: u16 = 8;
    pub const PRIORITY: u16 = 9;
    /// Master interface index.
    pub const MASTER: u16 = 10;
    /// Wireless extension.
    pub const WIRELESS: u16 = 11;
    /// Protocol specific info.
    pub const PROTINFO: u16 = 12;
    /// Transmit queue length.
    pub const TXQLEN: u16 = 13;
    pub const MAP: u16 = 14;
    pub const WEIGHT: u16 = 15;
    /// Operational state.
    pub const OPERSTATE: u16 = 16;
    /// Link mode.
    pub const LINKMODE: u16 = 17;
    /// Link info (nested: kind, data).
    pub const LINKINFO: u16 = 18;
    pub const NET_NS_PID: u16 = 19;
    /// Interface alias.
    pub const IFALIAS: u16 = 20;
    pub const NUM_VF: u16 = 21;
    pub const VFINFO_LIST: u16 = 22;
    /// 64-bit statistics.
    pub const STATS64: u16 = 23;
    pub const VF_PORTS: u16 = 24;
    pub const PORT_SELF: u16 = 25;
    pub const AF_SPEC: u16 = 26;
    /// Interface group.
    pub const GROUP: u16 = 27;
    pub const NET_NS_FD: u16 = 28;
    /// Extended info mask.
    pub const EXT_MASK: u16 = 29;
    pub const PROMISCUITY: u16 = 30;
    pub const NUM_TX_QUEUES: u16 = 31;
    pub const NUM_RX_QUEUES: u16 = 32;
    /// Carrier state (0/1).
    pub const CARRIER: u16 = 33;
    pub const PHYS_PORT_ID: u16 = 34;
    pub const CARRIER_CHANGES: u16 = 35;
};

/// Link info attribute types (IFLA_INFO_*).
pub const InfoAttr = struct {
    pub const UNSPEC: u16 = 0;
    /// Interface type name (e.g., "veth", "bridge").
    pub const KIND: u16 = 1;
    /// Type-specific data.
    pub const DATA: u16 = 2;
    /// Type-specific statistics.
    pub const XSTATS: u16 = 3;
    /// Slave type name.
    pub const SLAVE_KIND: u16 = 4;
    /// Slave-specific data.
    pub const SLAVE_DATA: u16 = 5;
};

/// Link operational state (IF_OPER_*).
pub const OperState = struct {
    pub const UNKNOWN: u8 = 0;
    pub const NOTPRESENT: u8 = 1;
    pub const DOWN: u8 = 2;
    pub const LOWERLAYERDOWN: u8 = 3;
    pub const TESTING: u8 = 4;
    pub const DORMANT: u8 = 5;
    pub const UP: u8 = 6;
};

/// Virtual interface kinds.
///
/// Used to identify virtual network interface types. Most virtual types
/// (veth, bridge, vlan, etc.) are considered "virtual" for filtering purposes.
pub const InfoKind = enum {
    veth,
    vlan,
    bridge,
    ipvlan,
    ipvtap,
    macvlan,
    macvtap,
    gretap,
    gretap6,
    ipip,
    ip6tnl,
    sit,
    gre,
    gre6,
    vti,
    vrf,
    gtp,
    wireguard,
    xfrm,
    macsec,
    hsr,
    geneve,
    netkit,
    dummy,
    other,

    /// Parse an InfoKind from a string.
    pub fn fromString(s: []const u8) InfoKind {
        const kinds = .{
            .{ "veth", .veth },
            .{ "vlan", .vlan },
            .{ "bridge", .bridge },
            .{ "ipvlan", .ipvlan },
            .{ "ipvtap", .ipvtap },
            .{ "macvlan", .macvlan },
            .{ "macvtap", .macvtap },
            .{ "gretap", .gretap },
            .{ "ip6gretap", .gretap6 },
            .{ "ipip", .ipip },
            .{ "ip6tnl", .ip6tnl },
            .{ "sit", .sit },
            .{ "gre", .gre },
            .{ "ip6gre", .gre6 },
            .{ "vti", .vti },
            .{ "vrf", .vrf },
            .{ "gtp", .gtp },
            .{ "wireguard", .wireguard },
            .{ "xfrm", .xfrm },
            .{ "macsec", .macsec },
            .{ "hsr", .hsr },
            .{ "geneve", .geneve },
            .{ "netkit", .netkit },
            .{ "dummy", .dummy },
        };
        inline for (kinds) |kv| {
            if (mem.eql(u8, s, kv[0])) return kv[1];
        }
        return .other;
    }

    /// Check if this interface type is virtual.
    ///
    /// Virtual interfaces (veth, bridge, vlan, tunnels, etc.) are typically
    /// created by software and don't correspond to physical hardware.
    /// The `dummy` type and unknown types are not considered virtual.
    pub fn isVirtual(self: InfoKind) bool {
        return switch (self) {
            .dummy => false,
            .other => false,
            else => true,
        };
    }
};

/// Parsed link message.
///
/// Contains the interface header and optional attributes like name, MAC address,
/// MTU, carrier status, and link kind.
pub const LinkMessage = struct {
    /// The interface info header.
    header: IfInfoMsg,
    /// Interface name (e.g., "eth0").
    name: ?[]const u8 = null,
    /// Hardware address (MAC), usually 6 bytes for Ethernet.
    address: ?[]const u8 = null,
    /// Maximum transmission unit.
    mtu: ?u32 = null,
    /// Carrier status (1 = carrier present).
    carrier: ?u8 = null,
    /// Operational state (IF_OPER_*).
    operstate: ?u8 = null,
    /// Link kind for virtual interfaces.
    link_kind: ?InfoKind = null,

    /// Parse a link message from payload bytes (after netlink header).
    pub fn parse(payload: []const u8) ?LinkMessage {
        const header = IfInfoMsg.fromBytes(payload) orelse return null;
        var result = LinkMessage{ .header = header };

        var iter = message.AttributeIterator.init(payload[IfInfoMsg.SIZE..]);
        while (iter.next()) |item| {
            const attr_type = item.attr.type & 0x7fff; // Mask out NLA_F_NESTED etc
            switch (attr_type) {
                Attr.IFNAME => {
                    if (item.attr.payload(item.data)) |data| {
                        result.name = mem.sliceTo(data, 0);
                    }
                },
                Attr.ADDRESS => {
                    result.address = item.attr.payload(item.data);
                },
                Attr.MTU => {
                    result.mtu = item.attr.payloadAs(u32, item.data);
                },
                Attr.CARRIER => {
                    result.carrier = item.attr.payloadAs(u8, item.data);
                },
                Attr.OPERSTATE => {
                    result.operstate = item.attr.payloadAs(u8, item.data);
                },
                Attr.LINKINFO => {
                    result.link_kind = parseLinkInfo(item.attr.payload(item.data) orelse continue);
                },
                else => {},
            }
        }
        return result;
    }

    fn parseLinkInfo(payload: []const u8) ?InfoKind {
        var iter = message.AttributeIterator.init(payload);
        while (iter.next()) |item| {
            const attr_type = item.attr.type & 0x7fff;
            if (attr_type == InfoAttr.KIND) {
                if (item.attr.payload(item.data)) |data| {
                    return InfoKind.fromString(mem.sliceTo(data, 0));
                }
            }
        }
        return null;
    }

    /// Get the interface index.
    pub fn ifindex(self: LinkMessage) u32 {
        return @intCast(self.header.index);
    }

    /// Check if the interface has the UP flag set.
    pub fn isUp(self: LinkMessage) bool {
        return self.header.flags & rtnetlink.IFF.UP != 0;
    }

    /// Check if the interface has carrier (link detected).
    pub fn hasCarrier(self: LinkMessage) bool {
        return (self.carrier orelse 0) == 1;
    }

    /// Check if this is a virtual interface.
    pub fn isVirtual(self: LinkMessage) bool {
        if (self.link_kind) |kind| {
            return kind.isVirtual();
        }
        return false;
    }

    /// Get the MAC address as a 6-byte array.
    pub fn getMacAddress(self: LinkMessage) ?[6]u8 {
        const addr = self.address orelse return null;
        if (addr.len < 6) return null;
        return addr[0..6].*;
    }
};

/// Builder for link messages.
pub const LinkMessageBuilder = struct {
    buffer: [4096]u8 = undefined,
    len: usize = 0,

    /// Create a new empty builder.
    pub fn init() LinkMessageBuilder {
        return .{};
    }

    /// Create a RTM_GETLINK dump request for all interfaces.
    pub fn getLink(family: u8) LinkMessageBuilder {
        var builder = LinkMessageBuilder.init();
        builder.addHeader(rtnetlink.Type.GETLINK, message.Flags.REQUEST | message.Flags.DUMP);
        builder.addIfInfoMsg(.{
            .family = family,
            .type = 0,
            .index = 0,
            .flags = 0,
            .change = 0,
        });
        return builder;
    }

    /// Create a RTM_SETLINK request for a specific interface.
    pub fn setLink(ifindex: u32) LinkMessageBuilder {
        var builder = LinkMessageBuilder.init();
        builder.addHeader(rtnetlink.Type.SETLINK, message.Flags.REQUEST | message.Flags.ACK);
        builder.addIfInfoMsg(.{
            .family = rtnetlink.AF.UNSPEC,
            .type = 0,
            .index = @intCast(ifindex),
            .flags = 0,
            .change = 0,
        });
        return builder;
    }

    /// Set the IFF_UP flag to bring the interface up.
    pub fn setUp(self: *LinkMessageBuilder) *LinkMessageBuilder {
        const ifinfo_offset = message.Header.SIZE;
        const ifinfo = mem.bytesAsValue(IfInfoMsg, self.buffer[ifinfo_offset..][0..IfInfoMsg.SIZE]);
        ifinfo.flags |= rtnetlink.IFF.UP;
        ifinfo.change |= rtnetlink.IFF.UP;
        return self;
    }

    /// Clear the IFF_UP flag to bring the interface down.
    pub fn setDown(self: *LinkMessageBuilder) *LinkMessageBuilder {
        const ifinfo_offset = message.Header.SIZE;
        const ifinfo = mem.bytesAsValue(IfInfoMsg, self.buffer[ifinfo_offset..][0..IfInfoMsg.SIZE]);
        ifinfo.flags &= ~rtnetlink.IFF.UP;
        ifinfo.change |= rtnetlink.IFF.UP;
        return self;
    }

    /// Set the interface name.
    pub fn setName(self: *LinkMessageBuilder, name: []const u8) *LinkMessageBuilder {
        self.addAttrString(Attr.IFNAME, name);
        return self;
    }

    fn addHeader(self: *LinkMessageBuilder, msg_type: u16, flags: u16) void {
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

    fn addIfInfoMsg(self: *LinkMessageBuilder, info: IfInfoMsg) void {
        @memcpy(self.buffer[self.len..][0..IfInfoMsg.SIZE], info.toBytes());
        self.len += IfInfoMsg.SIZE;
    }

    fn addAttrString(self: *LinkMessageBuilder, attr_type: u16, value: []const u8) void {
        const attr_len: u16 = @intCast(message.Attribute.HEADER_SIZE + value.len + 1);
        const aligned_len = message.align4(attr_len);

        self.buffer[self.len] = @truncate(attr_len);
        self.buffer[self.len + 1] = @truncate(attr_len >> 8);
        self.buffer[self.len + 2] = @truncate(attr_type);
        self.buffer[self.len + 3] = @truncate(attr_type >> 8);
        self.len += message.Attribute.HEADER_SIZE;

        @memcpy(self.buffer[self.len..][0..value.len], value);
        self.buffer[self.len + value.len] = 0;
        self.len += aligned_len - message.Attribute.HEADER_SIZE;
    }

    /// Build the final message bytes.
    pub fn build(self: *LinkMessageBuilder) []const u8 {
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

test "ifinfomsg size" {
    try std.testing.expectEqual(@as(usize, 16), IfInfoMsg.SIZE);
}

test "info kind from string" {
    try std.testing.expectEqual(InfoKind.veth, InfoKind.fromString("veth"));
    try std.testing.expectEqual(InfoKind.bridge, InfoKind.fromString("bridge"));
    try std.testing.expectEqual(InfoKind.wireguard, InfoKind.fromString("wireguard"));
    try std.testing.expectEqual(InfoKind.dummy, InfoKind.fromString("dummy"));
    try std.testing.expectEqual(InfoKind.other, InfoKind.fromString("unknown_type"));
}

test "info kind is virtual" {
    try std.testing.expect(InfoKind.veth.isVirtual());
    try std.testing.expect(InfoKind.bridge.isVirtual());
    try std.testing.expect(InfoKind.wireguard.isVirtual());
    try std.testing.expect(InfoKind.vlan.isVirtual());
    try std.testing.expect(!InfoKind.dummy.isVirtual());
    try std.testing.expect(!InfoKind.other.isVirtual());
}

test "parse link message" {
    // Construct a minimal link message payload
    var payload: [64]u8 = undefined;
    @memset(&payload, 0);

    // IfInfoMsg header
    payload[0] = rtnetlink.AF.PACKET; // family
    payload[4] = 2; // index = 2 (little-endian i32)
    payload[8] = rtnetlink.IFF.UP; // flags = UP

    // IFLA_IFNAME attribute at offset 16
    payload[16] = 9; // len = 9 (4 header + 5 bytes "eth0\0")
    payload[18] = Attr.IFNAME; // type
    @memcpy(payload[20..25], "eth0\x00");

    // IFLA_MTU attribute at offset 28 (aligned)
    payload[28] = 8; // len = 8 (4 header + 4 bytes)
    payload[30] = Attr.MTU; // type
    payload[32] = 0xDC; // 1500 little-endian
    payload[33] = 0x05;

    const link = LinkMessage.parse(&payload).?;
    try std.testing.expectEqual(@as(u32, 2), link.ifindex());
    try std.testing.expect(link.isUp());
    try std.testing.expectEqualStrings("eth0", link.name.?);
    try std.testing.expectEqual(@as(u32, 1500), link.mtu.?);
}

test "link message builder getLink" {
    var builder = LinkMessageBuilder.getLink(rtnetlink.AF.PACKET);
    const data = builder.build();

    // Check header
    const header = message.Header.fromBytes(data).?;
    try std.testing.expectEqual(@as(u16, rtnetlink.Type.GETLINK), header.type);
    try std.testing.expectEqual(message.Flags.REQUEST | message.Flags.DUMP, header.flags);

    // Check ifinfomsg
    const ifinfo = IfInfoMsg.fromBytes(data[message.Header.SIZE..]).?;
    try std.testing.expectEqual(@as(u8, rtnetlink.AF.PACKET), ifinfo.family);
}

test "link message builder setLink with up" {
    var builder = LinkMessageBuilder.setLink(5);
    _ = builder.setUp();
    const data = builder.build();

    const header = message.Header.fromBytes(data).?;
    try std.testing.expectEqual(@as(u16, rtnetlink.Type.SETLINK), header.type);

    const ifinfo = IfInfoMsg.fromBytes(data[message.Header.SIZE..]).?;
    try std.testing.expectEqual(@as(i32, 5), ifinfo.index);
    try std.testing.expect(ifinfo.flags & rtnetlink.IFF.UP != 0);
    try std.testing.expect(ifinfo.change & rtnetlink.IFF.UP != 0);
}

test "link message getMacAddress" {
    var link = LinkMessage{ .header = undefined };
    link.address = &[_]u8{ 0x00, 0x11, 0x22, 0x33, 0x44, 0x55 };

    const mac = link.getMacAddress().?;
    try std.testing.expectEqual([_]u8{ 0x00, 0x11, 0x22, 0x33, 0x44, 0x55 }, mac);
}

test "link message getMacAddress too short" {
    var link = LinkMessage{ .header = undefined };
    link.address = &[_]u8{ 0x00, 0x11, 0x22 };

    try std.testing.expect(link.getMacAddress() == null);
}

test "link message getMacAddress null" {
    var link = LinkMessage{ .header = undefined };
    link.address = null;

    try std.testing.expect(link.getMacAddress() == null);
}

test "link message parse too short" {
    var payload: [8]u8 = undefined; // Need 16 bytes for IfInfoMsg
    @memset(&payload, 0);

    try std.testing.expect(LinkMessage.parse(&payload) == null);
}

test "link message hasCarrier true" {
    var link = LinkMessage{ .header = undefined };
    link.carrier = 1;
    try std.testing.expect(link.hasCarrier());
}

test "link message hasCarrier false" {
    var link = LinkMessage{ .header = undefined };
    link.carrier = 0;
    try std.testing.expect(!link.hasCarrier());
}

test "link message hasCarrier null" {
    var link = LinkMessage{ .header = undefined };
    link.carrier = null;
    try std.testing.expect(!link.hasCarrier());
}

test "link message isVirtual with kind" {
    var link = LinkMessage{ .header = undefined };
    link.link_kind = .veth;
    try std.testing.expect(link.isVirtual());

    link.link_kind = .bridge;
    try std.testing.expect(link.isVirtual());
}

test "link message isVirtual without kind" {
    var link = LinkMessage{ .header = undefined };
    link.link_kind = null;
    try std.testing.expect(!link.isVirtual());
}

test "link message builder setName" {
    var builder = LinkMessageBuilder.setLink(3);
    _ = builder.setName("renamed0");
    const data = builder.build();

    const header = message.Header.fromBytes(data).?;
    try std.testing.expectEqual(@as(u16, rtnetlink.Type.SETLINK), header.type);

    // Verify IFLA_IFNAME attribute is present after ifinfomsg
    const attr_offset = message.Header.SIZE + IfInfoMsg.SIZE;
    const attr = message.Attribute.fromBytes(data[attr_offset..]).?;
    try std.testing.expectEqual(@as(u16, Attr.IFNAME), attr.type);

    const name_data = attr.payload(data[attr_offset..]).?;
    try std.testing.expectEqualStrings("renamed0", mem.sliceTo(name_data, 0));
}

test "ifinfomsg fromBytes too short" {
    var bytes: [8]u8 = undefined;
    @memset(&bytes, 0);
    try std.testing.expect(IfInfoMsg.fromBytes(&bytes) == null);
}

test "ifinfomsg toBytes roundtrip" {
    const info = IfInfoMsg{
        .family = rtnetlink.AF.PACKET,
        .type = 1,
        .index = 5,
        .flags = rtnetlink.IFF.UP | rtnetlink.IFF.RUNNING,
        .change = rtnetlink.IFF.UP,
    };

    const bytes = info.toBytes();
    const parsed = IfInfoMsg.fromBytes(bytes).?;

    try std.testing.expectEqual(info.family, parsed.family);
    try std.testing.expectEqual(info.type, parsed.type);
    try std.testing.expectEqual(info.index, parsed.index);
    try std.testing.expectEqual(info.flags, parsed.flags);
    try std.testing.expectEqual(info.change, parsed.change);
}

test "parse link message with carrier" {
    var payload: [40]u8 = undefined;
    @memset(&payload, 0);

    // IfInfoMsg header (16 bytes)
    payload[0] = rtnetlink.AF.PACKET;
    payload[4] = 1; // index = 1

    // IFLA_CARRIER attribute at offset 16
    payload[16] = 5; // len = 5 (4 header + 1 byte)
    payload[18] = Attr.CARRIER;
    payload[20] = 1; // carrier = 1

    const link = LinkMessage.parse(&payload).?;
    try std.testing.expectEqual(@as(u8, 1), link.carrier.?);
    try std.testing.expect(link.hasCarrier());
}

test "parse link message with operstate" {
    var payload: [40]u8 = undefined;
    @memset(&payload, 0);

    payload[0] = rtnetlink.AF.PACKET;
    payload[4] = 2; // index = 2

    // IFLA_OPERSTATE attribute at offset 16
    payload[16] = 5; // len = 5
    payload[18] = Attr.OPERSTATE;
    payload[20] = OperState.UP;

    const link = LinkMessage.parse(&payload).?;
    try std.testing.expectEqual(@as(u8, OperState.UP), link.operstate.?);
}

test "all info kinds" {
    // Test a few more kinds
    try std.testing.expectEqual(InfoKind.ipvlan, InfoKind.fromString("ipvlan"));
    try std.testing.expectEqual(InfoKind.macvlan, InfoKind.fromString("macvlan"));
    try std.testing.expectEqual(InfoKind.gre, InfoKind.fromString("gre"));
    try std.testing.expectEqual(InfoKind.vrf, InfoKind.fromString("vrf"));
    try std.testing.expectEqual(InfoKind.geneve, InfoKind.fromString("geneve"));

    // All these should be virtual
    try std.testing.expect(InfoKind.ipvlan.isVirtual());
    try std.testing.expect(InfoKind.macvlan.isVirtual());
    try std.testing.expect(InfoKind.gre.isVirtual());
    try std.testing.expect(InfoKind.vrf.isVirtual());
    try std.testing.expect(InfoKind.geneve.isVirtual());
}
