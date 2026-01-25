//! Address message structures and attributes.
//!
//! This module handles parsing and building of RTM_*ADDR messages used for
//! querying and configuring IP addresses on network interfaces.

const std = @import("std");
const mem = std.mem;
const message = @import("message.zig");
const rtnetlink = @import("rtnetlink.zig");

/// Interface address message header (struct ifaddrmsg).
///
/// This structure follows the netlink header in address messages.
pub const IfAddrMsg = extern struct {
    /// Address family (AF_INET or AF_INET6).
    family: u8,
    /// Prefix length (CIDR notation).
    prefixlen: u8,
    /// Address flags (IFA_F_*).
    flags: u8,
    /// Address scope (RT_SCOPE_*).
    scope: u8,
    /// Interface index.
    index: u32,

    pub const SIZE: usize = 8;

    comptime {
        std.debug.assert(@sizeOf(IfAddrMsg) == SIZE);
    }

    /// Parse from raw bytes.
    pub fn fromBytes(bytes: []const u8) ?IfAddrMsg {
        if (bytes.len < SIZE) return null;
        return mem.bytesAsValue(IfAddrMsg, bytes[0..SIZE]).*;
    }

    /// Get raw bytes.
    pub fn toBytes(self: *const IfAddrMsg) *const [SIZE]u8 {
        return @ptrCast(self);
    }
};

/// Address attribute types (IFA_*).
pub const Attr = struct {
    pub const UNSPEC: u16 = 0;
    /// Interface address.
    pub const ADDRESS: u16 = 1;
    /// Local address (for point-to-point).
    pub const LOCAL: u16 = 2;
    /// Interface name label.
    pub const LABEL: u16 = 3;
    /// Broadcast address.
    pub const BROADCAST: u16 = 4;
    /// Anycast address.
    pub const ANYCAST: u16 = 5;
    /// Address cache info.
    pub const CACHEINFO: u16 = 6;
    /// Multicast address.
    pub const MULTICAST: u16 = 7;
    /// Extended address flags.
    pub const FLAGS: u16 = 8;
};

/// Address flags (IFA_F_*).
pub const Flags = struct {
    /// Secondary/alias address.
    pub const SECONDARY: u8 = 0x01;
    /// No duplicate address detection.
    pub const NODAD: u8 = 0x02;
    /// Optimistic address.
    pub const OPTIMISTIC: u8 = 0x04;
    /// DAD failed.
    pub const DADFAILED: u8 = 0x08;
    /// Home address (Mobile IPv6).
    pub const HOMEADDRESS: u8 = 0x10;
    /// Deprecated address.
    pub const DEPRECATED: u8 = 0x20;
    /// Tentative address.
    pub const TENTATIVE: u8 = 0x40;
    /// Permanent address.
    pub const PERMANENT: u8 = 0x80;
};

/// Parsed address message.
///
/// Contains the address header and optional attributes like the IP address,
/// local address, broadcast, and label.
pub const AddressMessage = struct {
    /// The address message header.
    header: IfAddrMsg,
    /// The IP address (4 bytes for IPv4, 16 bytes for IPv6).
    address: ?[]const u8 = null,
    /// Local address (for point-to-point interfaces).
    local: ?[]const u8 = null,
    /// Broadcast address.
    broadcast: ?[]const u8 = null,
    /// Interface label.
    label: ?[]const u8 = null,

    /// Parse an address message from payload bytes (after netlink header).
    pub fn parse(payload: []const u8) ?AddressMessage {
        const header = IfAddrMsg.fromBytes(payload) orelse return null;
        var result = AddressMessage{ .header = header };

        var iter = message.AttributeIterator.init(payload[IfAddrMsg.SIZE..]);
        while (iter.next()) |item| {
            const attr_type = item.attr.type & 0x7fff;
            switch (attr_type) {
                Attr.ADDRESS => {
                    result.address = item.attr.payload(item.data);
                },
                Attr.LOCAL => {
                    result.local = item.attr.payload(item.data);
                },
                Attr.BROADCAST => {
                    result.broadcast = item.attr.payload(item.data);
                },
                Attr.LABEL => {
                    if (item.attr.payload(item.data)) |data| {
                        result.label = mem.sliceTo(data, 0);
                    }
                },
                else => {},
            }
        }
        return result;
    }

    /// Get the interface index.
    pub fn ifindex(self: AddressMessage) u32 {
        return self.header.index;
    }

    /// Get the prefix length (CIDR notation).
    pub fn prefixLen(self: AddressMessage) u8 {
        return self.header.prefixlen;
    }

    /// Get the address family.
    pub fn family(self: AddressMessage) u8 {
        return self.header.family;
    }

    /// Check if this is an IPv4 address.
    pub fn isIPv4(self: AddressMessage) bool {
        return self.header.family == rtnetlink.AF.INET;
    }

    /// Check if this is an IPv6 address.
    pub fn isIPv6(self: AddressMessage) bool {
        return self.header.family == rtnetlink.AF.INET6;
    }

    /// Get the IPv4 address as a 4-byte array.
    pub fn getIPv4Address(self: AddressMessage) ?[4]u8 {
        if (!self.isIPv4()) return null;
        const addr = self.address orelse return null;
        if (addr.len < 4) return null;
        return addr[0..4].*;
    }

    /// Get the IPv6 address as a 16-byte array.
    pub fn getIPv6Address(self: AddressMessage) ?[16]u8 {
        if (!self.isIPv6()) return null;
        const addr = self.address orelse return null;
        if (addr.len < 16) return null;
        return addr[0..16].*;
    }
};

/// Builder for address messages.
pub const AddressMessageBuilder = struct {
    buffer: [4096]u8 = undefined,
    len: usize = 0,

    /// Create a new empty builder.
    pub fn init() AddressMessageBuilder {
        return .{};
    }

    /// Create a RTM_GETADDR dump request for all addresses.
    pub fn getAddresses(family: u8) AddressMessageBuilder {
        return getAddressesFiltered(family, null);
    }

    /// Create a RTM_GETADDR dump request, optionally filtered by interface.
    pub fn getAddressesFiltered(family: u8, ifindex: ?u32) AddressMessageBuilder {
        var builder = AddressMessageBuilder.init();
        builder.addHeader(rtnetlink.Type.GETADDR, message.Flags.REQUEST | message.Flags.DUMP);
        builder.addIfAddrMsg(.{
            .family = family,
            .prefixlen = 0,
            .flags = 0,
            .scope = 0,
            .index = ifindex orelse 0,
        });
        return builder;
    }

    /// Create a RTM_NEWADDR request to add an address.
    pub fn newAddress(ifindex: u32, family: u8, prefix_len: u8) AddressMessageBuilder {
        var builder = AddressMessageBuilder.init();
        builder.addHeader(rtnetlink.Type.NEWADDR, message.Flags.REQUEST | message.Flags.ACK | message.Flags.CREATE | message.Flags.EXCL);
        builder.addIfAddrMsg(.{
            .family = family,
            .prefixlen = prefix_len,
            .flags = 0,
            .scope = rtnetlink.IFA_SCOPE.UNIVERSE,
            .index = ifindex,
        });
        return builder;
    }

    /// Create a RTM_DELADDR request to delete an address.
    pub fn delAddress(ifindex: u32, family: u8, prefix_len: u8) AddressMessageBuilder {
        var builder = AddressMessageBuilder.init();
        builder.addHeader(rtnetlink.Type.DELADDR, message.Flags.REQUEST | message.Flags.ACK);
        builder.addIfAddrMsg(.{
            .family = family,
            .prefixlen = prefix_len,
            .flags = 0,
            .scope = 0,
            .index = ifindex,
        });
        return builder;
    }

    /// Set the IFA_ADDRESS attribute.
    pub fn setAddress(self: *AddressMessageBuilder, addr: []const u8) *AddressMessageBuilder {
        self.addAttrBytes(Attr.ADDRESS, addr);
        return self;
    }

    /// Set the IFA_LOCAL attribute.
    pub fn setLocal(self: *AddressMessageBuilder, addr: []const u8) *AddressMessageBuilder {
        self.addAttrBytes(Attr.LOCAL, addr);
        return self;
    }

    /// Set both IFA_ADDRESS and IFA_LOCAL for an IPv4 address.
    pub fn setIPv4(self: *AddressMessageBuilder, addr: [4]u8) *AddressMessageBuilder {
        _ = self.setAddress(&addr);
        return self.setLocal(&addr);
    }

    /// Set both IFA_ADDRESS and IFA_LOCAL for an IPv6 address.
    pub fn setIPv6(self: *AddressMessageBuilder, addr: [16]u8) *AddressMessageBuilder {
        _ = self.setAddress(&addr);
        return self.setLocal(&addr);
    }

    fn addHeader(self: *AddressMessageBuilder, msg_type: u16, flags: u16) void {
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

    fn addIfAddrMsg(self: *AddressMessageBuilder, info: IfAddrMsg) void {
        @memcpy(self.buffer[self.len..][0..IfAddrMsg.SIZE], info.toBytes());
        self.len += IfAddrMsg.SIZE;
    }

    fn addAttrBytes(self: *AddressMessageBuilder, attr_type: u16, value: []const u8) void {
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

    /// Build the final message bytes.
    pub fn build(self: *AddressMessageBuilder) []const u8 {
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

test "ifaddrmsg size" {
    try std.testing.expectEqual(@as(usize, 8), IfAddrMsg.SIZE);
}

test "parse address message IPv4" {
    var payload: [32]u8 = undefined;
    @memset(&payload, 0);

    // IfAddrMsg header
    payload[0] = rtnetlink.AF.INET; // family
    payload[1] = 24; // prefixlen
    payload[2] = 0; // flags
    payload[3] = rtnetlink.RT_SCOPE.UNIVERSE; // scope
    payload[4] = 2; // index = 2

    // IFA_ADDRESS attribute at offset 8
    payload[8] = 8; // len = 8 (4 header + 4 bytes)
    payload[10] = Attr.ADDRESS; // type
    payload[12] = 192;
    payload[13] = 168;
    payload[14] = 1;
    payload[15] = 100;

    const addr = AddressMessage.parse(&payload).?;
    try std.testing.expectEqual(@as(u32, 2), addr.ifindex());
    try std.testing.expectEqual(@as(u8, 24), addr.prefixLen());
    try std.testing.expect(addr.isIPv4());
    try std.testing.expect(!addr.isIPv6());

    const ipv4 = addr.getIPv4Address().?;
    try std.testing.expectEqual([_]u8{ 192, 168, 1, 100 }, ipv4);
}

test "parse address message IPv6" {
    var payload: [48]u8 = undefined;
    @memset(&payload, 0);

    // IfAddrMsg header
    payload[0] = rtnetlink.AF.INET6; // family
    payload[1] = 64; // prefixlen
    payload[4] = 3; // index = 3

    // IFA_ADDRESS attribute at offset 8
    payload[8] = 20; // len = 20 (4 header + 16 bytes)
    payload[10] = Attr.ADDRESS; // type
    // fe80::1
    payload[12] = 0xfe;
    payload[13] = 0x80;
    payload[27] = 0x01;

    const addr = AddressMessage.parse(&payload).?;
    try std.testing.expectEqual(@as(u32, 3), addr.ifindex());
    try std.testing.expectEqual(@as(u8, 64), addr.prefixLen());
    try std.testing.expect(addr.isIPv6());
    try std.testing.expect(!addr.isIPv4());
    try std.testing.expect(addr.getIPv4Address() == null);
}

test "address message builder newAddress IPv4" {
    var builder = AddressMessageBuilder.newAddress(2, rtnetlink.AF.INET, 24);
    _ = builder.setIPv4(.{ 10, 0, 0, 1 });
    const data = builder.build();

    const header = message.Header.fromBytes(data).?;
    try std.testing.expectEqual(@as(u16, rtnetlink.Type.NEWADDR), header.type);

    const ifaddr = IfAddrMsg.fromBytes(data[message.Header.SIZE..]).?;
    try std.testing.expectEqual(@as(u8, rtnetlink.AF.INET), ifaddr.family);
    try std.testing.expectEqual(@as(u8, 24), ifaddr.prefixlen);
    try std.testing.expectEqual(@as(u32, 2), ifaddr.index);
}

test "address message builder getAddressesFiltered" {
    var builder = AddressMessageBuilder.getAddressesFiltered(rtnetlink.AF.INET, 5);
    const data = builder.build();

    const header = message.Header.fromBytes(data).?;
    try std.testing.expectEqual(@as(u16, rtnetlink.Type.GETADDR), header.type);
    try std.testing.expectEqual(message.Flags.REQUEST | message.Flags.DUMP, header.flags);

    const ifaddr = IfAddrMsg.fromBytes(data[message.Header.SIZE..]).?;
    try std.testing.expectEqual(@as(u32, 5), ifaddr.index);
}

test "address message parse too short" {
    var payload: [4]u8 = undefined; // Need 8 bytes for IfAddrMsg
    @memset(&payload, 0);

    try std.testing.expect(AddressMessage.parse(&payload) == null);
}

test "address message getIPv4Address wrong family" {
    var payload: [16]u8 = undefined;
    @memset(&payload, 0);
    payload[0] = rtnetlink.AF.INET6; // IPv6 family

    const addr = AddressMessage.parse(&payload).?;
    try std.testing.expect(addr.getIPv4Address() == null);
}

test "address message getIPv6Address wrong family" {
    var payload: [16]u8 = undefined;
    @memset(&payload, 0);
    payload[0] = rtnetlink.AF.INET; // IPv4 family

    const addr = AddressMessage.parse(&payload).?;
    try std.testing.expect(addr.getIPv6Address() == null);
}

test "address message getIPv4Address no address" {
    var payload: [16]u8 = undefined;
    @memset(&payload, 0);
    payload[0] = rtnetlink.AF.INET;

    const addr = AddressMessage.parse(&payload).?;
    try std.testing.expect(addr.getIPv4Address() == null);
}

test "ifaddrmsg toBytes roundtrip" {
    const info = IfAddrMsg{
        .family = rtnetlink.AF.INET,
        .prefixlen = 24,
        .flags = Flags.PERMANENT,
        .scope = rtnetlink.RT_SCOPE.UNIVERSE,
        .index = 3,
    };

    const bytes = info.toBytes();
    const parsed = IfAddrMsg.fromBytes(bytes).?;

    try std.testing.expectEqual(info.family, parsed.family);
    try std.testing.expectEqual(info.prefixlen, parsed.prefixlen);
    try std.testing.expectEqual(info.flags, parsed.flags);
    try std.testing.expectEqual(info.scope, parsed.scope);
    try std.testing.expectEqual(info.index, parsed.index);
}

test "address message builder delAddress" {
    var builder = AddressMessageBuilder.delAddress(2, rtnetlink.AF.INET, 24);
    _ = builder.setIPv4(.{ 10, 0, 0, 1 });
    const data = builder.build();

    const header = message.Header.fromBytes(data).?;
    try std.testing.expectEqual(@as(u16, rtnetlink.Type.DELADDR), header.type);
    try std.testing.expectEqual(message.Flags.REQUEST | message.Flags.ACK, header.flags);
}

test "address message builder newAddress IPv6" {
    var builder = AddressMessageBuilder.newAddress(3, rtnetlink.AF.INET6, 64);
    var ipv6_addr: [16]u8 = undefined;
    @memset(&ipv6_addr, 0);
    ipv6_addr[0] = 0xfe;
    ipv6_addr[1] = 0x80;
    ipv6_addr[15] = 0x01;
    _ = builder.setIPv6(ipv6_addr);
    const data = builder.build();

    const header = message.Header.fromBytes(data).?;
    try std.testing.expectEqual(@as(u16, rtnetlink.Type.NEWADDR), header.type);

    const ifaddr = IfAddrMsg.fromBytes(data[message.Header.SIZE..]).?;
    try std.testing.expectEqual(@as(u8, rtnetlink.AF.INET6), ifaddr.family);
    try std.testing.expectEqual(@as(u8, 64), ifaddr.prefixlen);
}

test "parse address message with label" {
    var payload: [32]u8 = undefined;
    @memset(&payload, 0);

    payload[0] = rtnetlink.AF.INET;
    payload[1] = 24;
    payload[4] = 2; // index

    // IFA_LABEL attribute at offset 8
    payload[8] = 9; // len = 9 (4 header + 5 bytes "eth0\0")
    payload[10] = Attr.LABEL;
    @memcpy(payload[12..17], "eth0\x00");

    const addr = AddressMessage.parse(&payload).?;
    try std.testing.expectEqualStrings("eth0", addr.label.?);
}

test "parse address message with broadcast" {
    var payload: [32]u8 = undefined;
    @memset(&payload, 0);

    payload[0] = rtnetlink.AF.INET;
    payload[1] = 24;
    payload[4] = 2;

    // IFA_BROADCAST at offset 8
    payload[8] = 8; // len = 8
    payload[10] = Attr.BROADCAST;
    payload[12] = 192;
    payload[13] = 168;
    payload[14] = 1;
    payload[15] = 255;

    const addr = AddressMessage.parse(&payload).?;
    try std.testing.expectEqual(@as(usize, 4), addr.broadcast.?.len);
    try std.testing.expectEqual(@as(u8, 255), addr.broadcast.?[3]);
}
