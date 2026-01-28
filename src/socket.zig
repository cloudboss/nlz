//! Netlink socket operations.
//!
//! This module provides the `Socket` type for communicating with the kernel
//! via the rtnetlink protocol. It handles socket creation, message
//! serialization/deserialization, and provides high-level methods for common
//! network configuration tasks.

const std = @import("std");
const mem = std.mem;
const posix = std.posix;
const linux = std.os.linux;

const message = @import("message.zig");
const rtnetlink = @import("rtnetlink.zig");
const link_mod = @import("link.zig");
const address_mod = @import("address.zig");
const route_mod = @import("route.zig");

pub const LinkMessage = link_mod.LinkMessage;
pub const AddressMessage = address_mod.AddressMessage;
pub const RouteMessage = route_mod.RouteMessage;

const LinkMessageBuilder = link_mod.LinkMessageBuilder;
const AddressMessageBuilder = address_mod.AddressMessageBuilder;
const RouteMessageBuilder = route_mod.RouteMessageBuilder;

/// Errors that can occur during netlink operations.
pub const Error = error{
    /// Failed to create netlink socket.
    SocketCreate,
    /// Failed to bind netlink socket.
    SocketBind,
    /// Failed to send message.
    Send,
    /// Failed to receive message.
    Receive,
    /// Kernel returned an error for the request.
    NetlinkError,
    /// Message data is invalid or malformed.
    InvalidMessage,
    /// Internal buffer is too small.
    BufferTooSmall,
};

/// Netlink socket address (struct sockaddr_nl).
const SockAddrNl = extern struct {
    family: u16 = linux.AF.NETLINK,
    pad: u16 = 0,
    pid: u32 = 0,
    groups: u32 = 0,
};

/// Netlink socket for rtnetlink communication.
///
/// Provides methods for querying and configuring network interfaces,
/// IP addresses, and routes via the kernel's netlink interface.
///
/// ## Example
///
/// ```zig
/// var socket = try Socket.open();
/// defer socket.close();
///
/// // List all interfaces
/// var links = try socket.getLinks(allocator);
/// defer links.deinit();
/// while (links.next()) |link| {
///     std.debug.print("{s}\n", .{link.name orelse "?"});
/// }
/// ```
pub const Socket = struct {
    fd: posix.fd_t,
    seq: u32 = 0,
    pid: u32 = 0,

    const RECV_BUFFER_SIZE = 32768;

    /// Open a new rtnetlink socket.
    pub fn open() Error!Socket {
        const fd = linux.socket(linux.AF.NETLINK, linux.SOCK.RAW | linux.SOCK.CLOEXEC, linux.NETLINK.ROUTE);
        const e = posix.errno(fd);
        if (e != .SUCCESS) {
            return Error.SocketCreate;
        }

        var addr = SockAddrNl{};
        const ret = linux.bind(@intCast(fd), @ptrCast(&addr), @sizeOf(SockAddrNl));
        const bind_e = posix.errno(ret);
        if (bind_e != .SUCCESS) {
            _ = linux.close(@intCast(fd));
            return Error.SocketBind;
        }

        // Get assigned port ID
        var bound_addr = SockAddrNl{};
        var addr_len: u32 = @sizeOf(SockAddrNl);
        _ = linux.getsockname(@intCast(fd), @ptrCast(&bound_addr), &addr_len);

        return Socket{
            .fd = @intCast(fd),
            .pid = bound_addr.pid,
        };
    }

    /// Close the socket.
    pub fn close(self: *Socket) void {
        posix.close(self.fd);
    }

    fn nextSeq(self: *Socket) u32 {
        self.seq +%= 1;
        return self.seq;
    }

    fn send(self: *Socket, data: []const u8) Error!void {
        var buf: [4096]u8 = undefined;
        if (data.len > buf.len) return Error.BufferTooSmall;

        @memcpy(buf[0..data.len], data);

        // Update sequence number and pid in the header
        const seq = self.nextSeq();
        buf[8] = @truncate(seq);
        buf[9] = @truncate(seq >> 8);
        buf[10] = @truncate(seq >> 16);
        buf[11] = @truncate(seq >> 24);
        buf[12] = @truncate(self.pid);
        buf[13] = @truncate(self.pid >> 8);
        buf[14] = @truncate(self.pid >> 16);
        buf[15] = @truncate(self.pid >> 24);

        var addr = SockAddrNl{};
        const ret = linux.sendto(self.fd, buf[0..data.len].ptr, data.len, 0, @ptrCast(&addr), @sizeOf(SockAddrNl));
        const e = posix.errno(ret);
        if (e != .SUCCESS) {
            return Error.Send;
        }
    }

    fn recv(self: *Socket, buffer: []u8) Error!usize {
        const ret = linux.recvfrom(self.fd, buffer.ptr, buffer.len, 0, null, null);
        const e = posix.errno(ret);
        if (e != .SUCCESS) {
            return Error.Receive;
        }
        return ret;
    }

    /// Execute a request and return the response messages.
    ///
    /// For dump requests, this collects all messages until NLMSG_DONE.
    /// For non-dump requests, this waits for ACK.
    pub fn execute(self: *Socket, request: []const u8, allocator: std.mem.Allocator) Error![]u8 {
        try self.send(request);

        var response: std.ArrayListUnmanaged(u8) = .empty;
        errdefer response.deinit(allocator);

        var recv_buf: [RECV_BUFFER_SIZE]u8 = undefined;

        while (true) {
            const n = try self.recv(&recv_buf);
            if (n == 0) break;

            var iter = message.MessageIterator.init(recv_buf[0..n]);
            while (iter.next()) |msg| {
                // Check for error response
                if (msg.isError()) {
                    const err = msg.getError() orelse 0;
                    if (err < 0) {
                        return Error.NetlinkError;
                    }
                    // err == 0 means ACK, we're done
                    return response.toOwnedSlice(allocator) catch return Error.BufferTooSmall;
                }

                // Check for end of dump
                if (msg.isDone()) {
                    return response.toOwnedSlice(allocator) catch return Error.BufferTooSmall;
                }

                // Append the entire message (header + payload) to response
                const msg_bytes = recv_buf[iter.offset - message.align4(msg.header.len) ..][0..msg.header.len];
                response.appendSlice(allocator, msg_bytes) catch return Error.BufferTooSmall;

                // If not multipart, we're done after this message
                if (!msg.isMulti()) {
                    return response.toOwnedSlice(allocator) catch return Error.BufferTooSmall;
                }
            }
        }

        return response.toOwnedSlice(allocator) catch return Error.BufferTooSmall;
    }

    // =========================================================================
    // High-level link operations
    // =========================================================================

    /// Get all network interfaces.
    pub fn getLinks(self: *Socket, allocator: std.mem.Allocator) Error!LinkIterator {
        var builder = LinkMessageBuilder.getLink(rtnetlink.AF.PACKET);
        const response = try self.execute(builder.build(), allocator);
        return LinkIterator.init(response, allocator);
    }

    /// Bring an interface up.
    pub fn setLinkUp(self: *Socket, ifindex: u32, allocator: std.mem.Allocator) Error!void {
        var builder = LinkMessageBuilder.setLink(ifindex);
        _ = builder.setUp();
        const response = try self.execute(builder.build(), allocator);
        allocator.free(response);
    }

    /// Rename an interface.
    pub fn setLinkName(self: *Socket, ifindex: u32, name: []const u8, allocator: std.mem.Allocator) Error!void {
        var builder = LinkMessageBuilder.setLink(ifindex);
        _ = builder.setName(name);
        const response = try self.execute(builder.build(), allocator);
        allocator.free(response);
    }

    // =========================================================================
    // High-level address operations
    // =========================================================================

    /// Get all addresses for a given address family.
    pub fn getAddresses(self: *Socket, family: u8, allocator: std.mem.Allocator) Error!AddressIterator {
        return self.getAddressesFiltered(family, null, allocator);
    }

    /// Get addresses, optionally filtered by interface index.
    pub fn getAddressesFiltered(self: *Socket, family: u8, ifindex: ?u32, allocator: std.mem.Allocator) Error!AddressIterator {
        var builder = AddressMessageBuilder.getAddressesFiltered(family, ifindex);
        const response = try self.execute(builder.build(), allocator);
        return AddressIterator.init(response, allocator);
    }

    /// Add an IPv4 address to an interface.
    pub fn addAddressIPv4(self: *Socket, ifindex: u32, addr: [4]u8, prefix_len: u8, allocator: std.mem.Allocator) Error!void {
        var builder = AddressMessageBuilder.newAddress(ifindex, rtnetlink.AF.INET, prefix_len);
        _ = builder.setIPv4(addr);
        const response = try self.execute(builder.build(), allocator);
        allocator.free(response);
    }

    /// Add an IPv6 address to an interface.
    pub fn addAddressIPv6(self: *Socket, ifindex: u32, addr: [16]u8, prefix_len: u8, allocator: std.mem.Allocator) Error!void {
        var builder = AddressMessageBuilder.newAddress(ifindex, rtnetlink.AF.INET6, prefix_len);
        _ = builder.setIPv6(addr);
        const response = try self.execute(builder.build(), allocator);
        allocator.free(response);
    }

    /// Delete an IPv4 address from an interface.
    pub fn delAddressIPv4(self: *Socket, ifindex: u32, addr: [4]u8, prefix_len: u8, allocator: std.mem.Allocator) Error!void {
        var builder = AddressMessageBuilder.delAddress(ifindex, rtnetlink.AF.INET, prefix_len);
        _ = builder.setIPv4(addr);
        const response = try self.execute(builder.build(), allocator);
        allocator.free(response);
    }

    /// Delete an IPv6 address from an interface.
    pub fn delAddressIPv6(self: *Socket, ifindex: u32, addr: [16]u8, prefix_len: u8, allocator: std.mem.Allocator) Error!void {
        var builder = AddressMessageBuilder.delAddress(ifindex, rtnetlink.AF.INET6, prefix_len);
        _ = builder.setIPv6(addr);
        const response = try self.execute(builder.build(), allocator);
        allocator.free(response);
    }

    /// Delete an address using an AddressMessage.
    ///
    /// This is useful when iterating over addresses and deleting specific ones.
    pub fn delAddress(self: *Socket, addr_msg: AddressMessage, allocator: std.mem.Allocator) Error!void {
        const addr = addr_msg.address orelse return Error.InvalidMessage;
        var builder = AddressMessageBuilder.delAddress(
            addr_msg.ifindex(),
            addr_msg.family(),
            addr_msg.prefixLen(),
        );
        _ = builder.setAddress(addr);
        if (addr_msg.local) |local| {
            _ = builder.setLocal(local);
        }
        const response = try self.execute(builder.build(), allocator);
        allocator.free(response);
    }

    // =========================================================================
    // High-level route operations
    // =========================================================================

    /// Add an IPv4 route.
    ///
    /// For a default route, use dst = {0,0,0,0} and prefix_len = 0.
    pub fn addRouteIPv4(self: *Socket, ifindex: u32, dst: [4]u8, gateway: [4]u8, prefix_len: u8, allocator: std.mem.Allocator) Error!void {
        var builder = RouteMessageBuilder.newRouteIPv4(dst, prefix_len, ifindex);
        _ = builder.setGatewayIPv4(gateway);
        const response = try self.execute(builder.build(), allocator);
        allocator.free(response);
    }

    /// Add an IPv6 route.
    ///
    /// For a default route, use dst = all zeros and prefix_len = 0.
    pub fn addRouteIPv6(self: *Socket, ifindex: u32, dst: [16]u8, gateway: [16]u8, prefix_len: u8, allocator: std.mem.Allocator) Error!void {
        var builder = RouteMessageBuilder.newRouteIPv6(dst, prefix_len, ifindex);
        _ = builder.setGatewayIPv6(gateway);
        const response = try self.execute(builder.build(), allocator);
        allocator.free(response);
    }

    /// Delete an IPv4 route.
    pub fn delRouteIPv4(self: *Socket, ifindex: u32, dst: [4]u8, prefix_len: u8, allocator: std.mem.Allocator) Error!void {
        var builder = RouteMessageBuilder.delRouteIPv4(dst, prefix_len, ifindex);
        const response = try self.execute(builder.build(), allocator);
        allocator.free(response);
    }

    /// Delete an IPv6 route.
    pub fn delRouteIPv6(self: *Socket, ifindex: u32, dst: [16]u8, prefix_len: u8, allocator: std.mem.Allocator) Error!void {
        var builder = RouteMessageBuilder.delRouteIPv6(dst, prefix_len, ifindex);
        const response = try self.execute(builder.build(), allocator);
        allocator.free(response);
    }
};

/// Iterator over link messages returned by `Socket.getLinks()`.
pub const LinkIterator = struct {
    data: []u8,
    allocator: std.mem.Allocator,
    msg_iter: message.MessageIterator,

    /// Create an iterator from response data.
    pub fn init(data: []u8, allocator: std.mem.Allocator) LinkIterator {
        return .{
            .data = data,
            .allocator = allocator,
            .msg_iter = message.MessageIterator.init(data),
        };
    }

    /// Get the next link message, or null if done.
    pub fn next(self: *LinkIterator) ?LinkMessage {
        while (self.msg_iter.next()) |msg| {
            if (msg.header.type == rtnetlink.Type.NEWLINK) {
                if (LinkMessage.parse(msg.payload)) |link| {
                    return link;
                }
            }
        }
        return null;
    }

    /// Free the underlying data.
    pub fn deinit(self: *LinkIterator) void {
        self.allocator.free(self.data);
    }
};

/// Iterator over address messages returned by `Socket.getAddresses()`.
pub const AddressIterator = struct {
    data: []u8,
    allocator: std.mem.Allocator,
    msg_iter: message.MessageIterator,

    /// Create an iterator from response data.
    pub fn init(data: []u8, allocator: std.mem.Allocator) AddressIterator {
        return .{
            .data = data,
            .allocator = allocator,
            .msg_iter = message.MessageIterator.init(data),
        };
    }

    /// Get the next address message, or null if done.
    pub fn next(self: *AddressIterator) ?AddressMessage {
        while (self.msg_iter.next()) |msg| {
            if (msg.header.type == rtnetlink.Type.NEWADDR) {
                if (AddressMessage.parse(msg.payload)) |addr| {
                    return addr;
                }
            }
        }
        return null;
    }

    /// Free the underlying data.
    pub fn deinit(self: *AddressIterator) void {
        self.allocator.free(self.data);
    }
};

// =============================================================================
// Tests
// =============================================================================

test "socket address size" {
    try std.testing.expectEqual(@as(usize, 12), @sizeOf(SockAddrNl));
}
