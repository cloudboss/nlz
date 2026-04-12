//! nlz - Netlink library for Zig
//!
//! A minimal rtnetlink implementation for network interface configuration.
//! Supports link, address, and route operations needed for DHCP clients
//! and network initialization.
//!
//! ## Example
//!
//! ```zig
//! const nlz = @import("nlz");
//!
//! var socket = try nlz.Socket.open();
//! defer socket.close();
//!
//! // List all network interfaces
//! var links = try socket.getLinks(allocator);
//! defer links.deinit();
//! while (links.next()) |link| {
//!     std.debug.print("Interface: {s} (index={})\n", .{
//!         link.name orelse "unknown",
//!         link.ifindex(),
//!     });
//! }
//!
//! // Bring an interface up
//! try socket.setLinkUp(2, allocator);
//!
//! // Add an IPv4 address
//! try socket.addAddressIPv4(2, .{ 192, 168, 1, 100 }, 24, allocator);
//!
//! // Add a default route
//! try socket.addRouteIPv4(2, .{ 0, 0, 0, 0 }, .{ 192, 168, 1, 1 }, 0, allocator);
//! ```

const std = @import("std");

const socket = @import("socket.zig");
const monitor = @import("monitor.zig");

/// Netlink socket for rtnetlink communication.
pub const Socket = socket.Socket;

/// Read-only netlink subscription for link state change notifications.
pub const LinkMonitor = monitor.LinkMonitor;

/// Iterator over link messages returned by `Socket.getLinks()`.
pub const LinkIterator = socket.LinkIterator;

/// Iterator over address messages returned by `Socket.getAddresses()`.
pub const AddressIterator = socket.AddressIterator;

/// Generic netlink message types and parsing utilities.
pub const message = @import("message.zig");

/// rtnetlink protocol constants (message types, address families, flags).
pub const rtnetlink = @import("rtnetlink.zig");

/// Link/interface message types and parsing.
pub const link = @import("link.zig");

/// Address message types and parsing.
pub const address = @import("address.zig");

/// Route message types and parsing.
pub const route = @import("route.zig");

/// Generic netlink message with header and payload.
pub const Message = message.Message;

/// Parsed link/interface message with name, MAC, MTU, carrier status, etc.
pub const LinkMessage = link.LinkMessage;

/// Parsed address message with IP address, prefix length, scope, etc.
pub const AddressMessage = address.AddressMessage;

/// Parsed route message with destination, gateway, output interface, etc.
pub const RouteMessage = route.RouteMessage;

/// Address family constants (INET, INET6, etc.).
pub const AF = rtnetlink.AF;

/// Interface flags (UP, BROADCAST, LOOPBACK, etc.).
pub const IFF = rtnetlink.IFF;

test {
    std.testing.refAllDecls(@This());
}
