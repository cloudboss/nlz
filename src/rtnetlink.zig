//! rtnetlink protocol definitions.
//!
//! This module contains constants from linux/rtnetlink.h and related headers
//! for the routing netlink protocol used for network configuration.

const std = @import("std");

/// rtnetlink message types (RTM_*).
pub const Type = struct {
    /// Base value for rtnetlink message types.
    pub const BASE: u16 = 16;

    // Link messages
    /// New link (interface) notification or response.
    pub const NEWLINK: u16 = 16;
    /// Delete link notification.
    pub const DELLINK: u16 = 17;
    /// Get link information.
    pub const GETLINK: u16 = 18;
    /// Set link attributes.
    pub const SETLINK: u16 = 19;

    // Address messages
    /// New address notification or response.
    pub const NEWADDR: u16 = 20;
    /// Delete address notification.
    pub const DELADDR: u16 = 21;
    /// Get address information.
    pub const GETADDR: u16 = 22;

    // Route messages
    /// New route notification or response.
    pub const NEWROUTE: u16 = 24;
    /// Delete route notification.
    pub const DELROUTE: u16 = 25;
    /// Get route information.
    pub const GETROUTE: u16 = 26;
};

/// Address families (AF_*).
pub const AF = struct {
    /// Unspecified address family.
    pub const UNSPEC: u8 = 0;
    /// IPv4.
    pub const INET: u8 = 2;
    /// IPv6.
    pub const INET6: u8 = 10;
    /// Low-level packet interface.
    pub const PACKET: u8 = 17;
};

/// Interface flags (IFF_*) from linux/if.h.
pub const IFF = struct {
    /// Interface is up.
    pub const UP: u32 = 1 << 0;
    /// Broadcast address valid.
    pub const BROADCAST: u32 = 1 << 1;
    /// Turn on debugging.
    pub const DEBUG: u32 = 1 << 2;
    /// Is a loopback net.
    pub const LOOPBACK: u32 = 1 << 3;
    /// Is point-to-point link.
    pub const POINTOPOINT: u32 = 1 << 4;
    /// Avoid use of trailers.
    pub const NOTRAILERS: u32 = 1 << 5;
    /// Resources allocated.
    pub const RUNNING: u32 = 1 << 6;
    /// No ARP protocol.
    pub const NOARP: u32 = 1 << 7;
    /// Receive all packets.
    pub const PROMISC: u32 = 1 << 8;
    /// Receive all multicast packets.
    pub const ALLMULTI: u32 = 1 << 9;
    /// Master of a load balancer.
    pub const MASTER: u32 = 1 << 10;
    /// Slave of a load balancer.
    pub const SLAVE: u32 = 1 << 11;
    /// Supports multicast.
    pub const MULTICAST: u32 = 1 << 12;
    /// Can set media type.
    pub const PORTSEL: u32 = 1 << 13;
    /// Auto media select active.
    pub const AUTOMEDIA: u32 = 1 << 14;
    /// Dialup device with changing addresses.
    pub const DYNAMIC: u32 = 1 << 15;
    /// Driver signals L1 up.
    pub const LOWER_UP: u32 = 1 << 16;
    /// Driver signals dormant.
    pub const DORMANT: u32 = 1 << 17;
    /// Echo sent packets.
    pub const ECHO: u32 = 1 << 18;
};

/// Route table IDs (RT_TABLE_*).
pub const RT_TABLE = struct {
    /// Unspecified table.
    pub const UNSPEC: u8 = 0;
    /// Compatibility routing table.
    pub const COMPAT: u8 = 252;
    /// Default routing table.
    pub const DEFAULT: u8 = 253;
    /// Main routing table.
    pub const MAIN: u8 = 254;
    /// Local routing table.
    pub const LOCAL: u8 = 255;
};

/// Route protocol identifiers (RTPROT_*).
pub const RTPROT = struct {
    /// Unspecified.
    pub const UNSPEC: u8 = 0;
    /// Route installed by ICMP redirects.
    pub const REDIRECT: u8 = 1;
    /// Route installed by kernel.
    pub const KERNEL: u8 = 2;
    /// Route installed during boot.
    pub const BOOT: u8 = 3;
    /// Route installed by administrator.
    pub const STATIC: u8 = 4;
    /// Route installed by DHCP.
    pub const DHCP: u8 = 16;
};

/// Route scope (RT_SCOPE_*).
pub const RT_SCOPE = struct {
    /// Global route.
    pub const UNIVERSE: u8 = 0;
    /// Site-local route.
    pub const SITE: u8 = 200;
    /// Link-local route.
    pub const LINK: u8 = 253;
    /// Host-local route.
    pub const HOST: u8 = 254;
    /// Route to nowhere.
    pub const NOWHERE: u8 = 255;
};

/// Route type (RTN_*).
pub const RTN = struct {
    /// Unknown route.
    pub const UNSPEC: u8 = 0;
    /// Gateway or direct route.
    pub const UNICAST: u8 = 1;
    /// Local address.
    pub const LOCAL: u8 = 2;
    /// Broadcast address.
    pub const BROADCAST: u8 = 3;
    /// Anycast address.
    pub const ANYCAST: u8 = 4;
    /// Multicast route.
    pub const MULTICAST: u8 = 5;
    /// Silently drop packets.
    pub const BLACKHOLE: u8 = 6;
    /// Destination is unreachable.
    pub const UNREACHABLE: u8 = 7;
    /// Administratively prohibited.
    pub const PROHIBIT: u8 = 8;
    /// Continue routing lookup in another table.
    pub const THROW: u8 = 9;
    /// NAT route.
    pub const NAT: u8 = 10;
    /// Refer to external resolver.
    pub const XRESOLVE: u8 = 11;
};

/// Address scope (IFA_SCOPE_*) - same values as route scope.
pub const IFA_SCOPE = RT_SCOPE;

// =============================================================================
// Tests
// =============================================================================

test "message type constants" {
    try std.testing.expectEqual(@as(u16, 16), Type.NEWLINK);
    try std.testing.expectEqual(@as(u16, 17), Type.DELLINK);
    try std.testing.expectEqual(@as(u16, 18), Type.GETLINK);
    try std.testing.expectEqual(@as(u16, 19), Type.SETLINK);
    try std.testing.expectEqual(@as(u16, 20), Type.NEWADDR);
    try std.testing.expectEqual(@as(u16, 21), Type.DELADDR);
    try std.testing.expectEqual(@as(u16, 22), Type.GETADDR);
    try std.testing.expectEqual(@as(u16, 24), Type.NEWROUTE);
    try std.testing.expectEqual(@as(u16, 25), Type.DELROUTE);
    try std.testing.expectEqual(@as(u16, 26), Type.GETROUTE);
}

test "address family constants" {
    try std.testing.expectEqual(@as(u8, 0), AF.UNSPEC);
    try std.testing.expectEqual(@as(u8, 2), AF.INET);
    try std.testing.expectEqual(@as(u8, 10), AF.INET6);
    try std.testing.expectEqual(@as(u8, 17), AF.PACKET);
}

test "interface flags" {
    try std.testing.expectEqual(@as(u32, 1), IFF.UP);
    try std.testing.expectEqual(@as(u32, 64), IFF.RUNNING);
    try std.testing.expectEqual(@as(u32, 0x10000), IFF.LOWER_UP);
}

test "route table constants" {
    try std.testing.expectEqual(@as(u8, 254), RT_TABLE.MAIN);
    try std.testing.expectEqual(@as(u8, 255), RT_TABLE.LOCAL);
}

test "route scope constants" {
    try std.testing.expectEqual(@as(u8, 0), RT_SCOPE.UNIVERSE);
    try std.testing.expectEqual(@as(u8, 253), RT_SCOPE.LINK);
    try std.testing.expectEqual(@as(u8, 254), RT_SCOPE.HOST);
}
