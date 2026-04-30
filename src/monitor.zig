//! Netlink multicast monitor for link state change notifications.
//!
//! `LinkMonitor` opens a dedicated rtnetlink socket subscribed to one or
//! more multicast groups and blocks on `poll()` until a notification arrives.
//! It is a read-only companion to `Socket`: the two use separate file
//! descriptors so that unsolicited multicast events never contaminate the
//! request/response stream on `Socket`.
//!
//! ## Subscribe before you act
//!
//! To avoid missing events, subscribe *before* triggering the state change
//! you want to observe. For a carrier wait, the correct sequence is:
//!
//! 1. Open the monitor (`LinkMonitor.open(nlz.rtnetlink.RTMGRP.LINK)`).
//! 2. Do a one-shot check of current state via `Socket.getLinks` — the
//!    link may already be up, in which case no notification is coming.
//! 3. If not yet up, call `waitCarrier` to block on the feed.
//!
//! ## Example
//!
//! ```zig
//! var mon = try LinkMonitor.open(nlz.rtnetlink.RTMGRP.LINK);
//! defer mon.close();
//!
//! try socket.setLinkUp(ifindex, allocator);
//! try mon.waitCarrier(ifindex, 10_000); // 10 second budget
//! ```

const std = @import("std");
const posix = std.posix;
const linux = std.os.linux;

const message = @import("message.zig");
const rtnetlink = @import("rtnetlink.zig");
const link = @import("link.zig");

pub const LinkMessage = link.LinkMessage;

/// Errors returned by `LinkMonitor` operations.
pub const Error = error{
    /// Failed to create netlink socket.
    SocketCreate,
    /// Failed to bind netlink socket.
    SocketBind,
    /// recv/poll failed.
    Receive,
    /// Deadline elapsed before the expected event arrived.
    Timeout,
};

const SockAddrNl = extern struct {
    family: u16 = linux.AF.NETLINK,
    pad: u16 = 0,
    pid: u32 = 0,
    groups: u32 = 0,
};

/// A read-only netlink subscription for monitoring link state changes.
///
/// The monitor owns a 4096-byte receive buffer. Parsed `LinkMessage`
/// values returned by `next()` borrow slices from that buffer and are
/// valid only until the next call to `next()` (or `close()`).
pub const LinkMonitor = struct {
    fd: posix.fd_t,
    buffer: [4096]u8 = undefined,
    buffer_len: usize = 0,
    iter_offset: usize = 0,

    /// Open a monitor subscribed to one or more RTMGRP_* groups.
    ///
    /// Pass `rtnetlink.RTMGRP.LINK` for link-state notifications; OR more
    /// groups together to subscribe to multiple feeds on one socket.
    pub fn open(groups: u32) Error!LinkMonitor {
        const fd = linux.socket(
            linux.AF.NETLINK,
            linux.SOCK.RAW | linux.SOCK.CLOEXEC,
            linux.NETLINK.ROUTE,
        );
        if (posix.errno(fd) != .SUCCESS) return Error.SocketCreate;
        errdefer _ = linux.close(@intCast(fd));

        var addr = SockAddrNl{ .groups = groups };
        const ret = linux.bind(@intCast(fd), @ptrCast(&addr), @sizeOf(SockAddrNl));
        if (posix.errno(ret) != .SUCCESS) return Error.SocketBind;

        return .{ .fd = @intCast(fd) };
    }

    /// Close the underlying socket.
    pub fn close(self: *LinkMonitor) void {
        _ = linux.close(self.fd);
    }

    /// Block up to `timeout_ms` waiting for the next link notification.
    ///
    /// Returns the parsed link message. Borrowed slices on the returned
    /// value (name, address, etc.) are valid until the next call.
    /// Pass a negative timeout for infinite wait.
    ///
    /// Messages on the subscribed feed that aren't `RTM_NEWLINK` are
    /// silently skipped — callers see only parseable link events.
    pub fn next(self: *LinkMonitor, timeout_ms: i32) Error!LinkMessage {
        while (true) {
            if (self.parseBuffered()) |lm| return lm;

            var pfd = [_]posix.pollfd{.{
                .fd = self.fd,
                .events = posix.POLL.IN,
                .revents = 0,
            }};
            const pr = posix.poll(&pfd, timeout_ms) catch return Error.Receive;
            if (pr == 0) return Error.Timeout;

            const n = linux.recvfrom(self.fd, &self.buffer, self.buffer.len, 0, null, null);
            if (posix.errno(n) != .SUCCESS) return Error.Receive;
            self.buffer_len = n;
            self.iter_offset = 0;
        }
    }

    /// Pull the next `RTM_NEWLINK` out of the already-received buffer.
    ///
    /// Returns `null` once the buffer is exhausted (or contains only
    /// non-link messages / unparseable trailing bytes). Separated from
    /// `next()` so it can be unit-tested without a real socket.
    fn parseBuffered(self: *LinkMonitor) ?LinkMessage {
        while (self.iter_offset < self.buffer_len) {
            const remaining = self.buffer[self.iter_offset..self.buffer_len];
            const msg = message.Message.fromBytes(remaining) orelse {
                // Unparseable trailing bytes — discard the rest.
                self.iter_offset = self.buffer_len;
                return null;
            };
            self.iter_offset += message.align4(msg.header.len);
            if (msg.header.type != rtnetlink.Type.NEWLINK) continue;
            if (link.LinkMessage.parse(msg.payload)) |lm| return lm;
        }
        return null;
    }

    /// Block until the interface at `ifindex` reports carrier up, or
    /// `total_timeout_ms` elapses.
    ///
    /// This is the common waiting primitive for "link is UP, wait for
    /// carrier before sending packets." It tracks a single deadline
    /// across multiple event receptions and ignores notifications for
    /// other interfaces.
    ///
    /// **Racing the subscription**: because the kernel may have brought
    /// carrier up between the caller's `setLinkUp` and this call, the
    /// caller should do a one-shot check via `Socket.getLinks` first and
    /// only fall back to `waitCarrier` if the link isn't already up.
    pub fn waitCarrier(
        self: *LinkMonitor,
        ifindex: u32,
        total_timeout_ms: i32,
    ) Error!void {
        const start = monotonicMs();
        while (true) {
            const elapsed = monotonicMs() - start;
            if (elapsed >= total_timeout_ms) return Error.Timeout;
            const remaining_ms: i32 = @intCast(@as(i64, total_timeout_ms) - elapsed);

            const lm = try self.next(remaining_ms);
            if (lm.ifindex() == ifindex and lm.hasCarrier()) return;
        }
    }
};

/// Monotonic milliseconds since some unspecified epoch. Used for relative
/// deadlines so we're immune to wall-clock jumps.
fn monotonicMs() i64 {
    var ts: linux.timespec = undefined;
    _ = linux.clock_gettime(.MONOTONIC, &ts);
    return @as(i64, ts.sec) * std.time.ms_per_s + @divTrunc(ts.nsec, std.time.ns_per_ms);
}

// =============================================================================
// Tests
// =============================================================================

const testing = std.testing;

/// Build a synthetic netlink message in `dst` and return the number of bytes
/// written. Used to feed hand-constructed frames into `parseBuffered` tests
/// without touching a real socket.
///
/// Layout: nlmsghdr (16) | ifinfomsg (16) | optional IFLA_CARRIER attr (8,
/// aligned). IFLA_IFNAME is omitted because `LinkMessage.parse` doesn't
/// require it and we want tests that focus on the fields that matter here.
fn writeTestNewLink(
    dst: []u8,
    msg_type: u16,
    ifindex: i32,
    carrier: ?u8,
) usize {
    @memset(dst, 0);
    const base: usize = message.Header.SIZE + link.IfInfoMsg.SIZE;
    var total: usize = base;
    if (carrier != null) total += 8; // aligned IFLA_CARRIER (len=5, padded)
    const total_u32: u32 = @intCast(total);

    // nlmsghdr
    dst[0] = @truncate(total_u32);
    dst[1] = @truncate(total_u32 >> 8);
    dst[2] = @truncate(total_u32 >> 16);
    dst[3] = @truncate(total_u32 >> 24);
    dst[4] = @truncate(msg_type);
    dst[5] = @truncate(msg_type >> 8);
    // flags/seq/pid remain zero

    // ifinfomsg: family=AF_UNSPEC, pad, type=0, index (i32 LE), flags, change
    const ifinfo_off: usize = message.Header.SIZE;
    dst[ifinfo_off] = 0; // family
    const idx_off = ifinfo_off + 4;
    const idx_u32: u32 = @bitCast(ifindex);
    dst[idx_off + 0] = @truncate(idx_u32);
    dst[idx_off + 1] = @truncate(idx_u32 >> 8);
    dst[idx_off + 2] = @truncate(idx_u32 >> 16);
    dst[idx_off + 3] = @truncate(idx_u32 >> 24);

    if (carrier) |c| {
        const attr_off = base;
        dst[attr_off + 0] = 5; // attr len = 4 (hdr) + 1 (value)
        dst[attr_off + 1] = 0;
        dst[attr_off + 2] = @truncate(link.Attr.CARRIER);
        dst[attr_off + 3] = @truncate(link.Attr.CARRIER >> 8);
        dst[attr_off + 4] = c;
    }

    return total;
}

test "RTMGRP bitmask constants are correct" {
    // Values come straight from Linux uapi/linux/rtnetlink.h: RTMGRP_* are
    // bitmasks intended for sockaddr_nl.nl_groups (not group numbers).
    try testing.expectEqual(@as(u32, 1), rtnetlink.RTMGRP.LINK);
    try testing.expectEqual(@as(u32, 2), rtnetlink.RTMGRP.NOTIFY);
    try testing.expectEqual(@as(u32, 4), rtnetlink.RTMGRP.NEIGH);
    try testing.expectEqual(@as(u32, 0x10), rtnetlink.RTMGRP.IPV4_IFADDR);
    try testing.expectEqual(@as(u32, 0x100), rtnetlink.RTMGRP.IPV6_IFADDR);
}

test "sockaddr_nl size matches kernel layout" {
    try testing.expectEqual(@as(usize, 12), @sizeOf(SockAddrNl));
}

test "parseBuffered returns null on empty buffer" {
    var mon: LinkMonitor = .{ .fd = -1 };
    mon.buffer_len = 0;
    mon.iter_offset = 0;
    try testing.expect(mon.parseBuffered() == null);
}

test "parseBuffered returns a single NEWLINK message" {
    var mon: LinkMonitor = .{ .fd = -1 };
    mon.buffer_len = writeTestNewLink(&mon.buffer, rtnetlink.Type.NEWLINK, 7, 1);
    mon.iter_offset = 0;

    const lm = mon.parseBuffered() orelse return error.TestExpectedSome;
    try testing.expectEqual(@as(u32, 7), lm.ifindex());
    try testing.expect(lm.hasCarrier());
    // Buffer should be fully consumed after one message.
    try testing.expect(mon.parseBuffered() == null);
}

test "parseBuffered walks multiple messages in a single datagram" {
    var mon: LinkMonitor = .{ .fd = -1 };
    const n1 = writeTestNewLink(mon.buffer[0..], rtnetlink.Type.NEWLINK, 3, 0);
    const n2 = writeTestNewLink(mon.buffer[n1..], rtnetlink.Type.NEWLINK, 4, 1);
    mon.buffer_len = n1 + n2;
    mon.iter_offset = 0;

    const a = mon.parseBuffered() orelse return error.TestExpectedSome;
    try testing.expectEqual(@as(u32, 3), a.ifindex());
    try testing.expect(!a.hasCarrier());

    const b = mon.parseBuffered() orelse return error.TestExpectedSome;
    try testing.expectEqual(@as(u32, 4), b.ifindex());
    try testing.expect(b.hasCarrier());

    try testing.expect(mon.parseBuffered() == null);
}

test "parseBuffered skips non-NEWLINK messages" {
    var mon: LinkMonitor = .{ .fd = -1 };
    // DELLINK first, then NEWLINK. The monitor should skip the DELLINK and
    // return the NEWLINK.
    const n1 = writeTestNewLink(mon.buffer[0..], rtnetlink.Type.DELLINK, 99, null);
    const n2 = writeTestNewLink(mon.buffer[n1..], rtnetlink.Type.NEWLINK, 42, 1);
    mon.buffer_len = n1 + n2;
    mon.iter_offset = 0;

    const lm = mon.parseBuffered() orelse return error.TestExpectedSome;
    try testing.expectEqual(@as(u32, 42), lm.ifindex());
}

test "parseBuffered drops unparseable trailing bytes" {
    var mon: LinkMonitor = .{ .fd = -1 };
    // One good NEWLINK followed by 3 garbage bytes (less than a header).
    const n = writeTestNewLink(mon.buffer[0..], rtnetlink.Type.NEWLINK, 11, 1);
    mon.buffer[n] = 0xff;
    mon.buffer[n + 1] = 0xff;
    mon.buffer[n + 2] = 0xff;
    mon.buffer_len = n + 3;
    mon.iter_offset = 0;

    const lm = mon.parseBuffered() orelse return error.TestExpectedSome;
    try testing.expectEqual(@as(u32, 11), lm.ifindex());

    // The trailing garbage should not be reported. A second call advances
    // iter_offset to buffer_len and returns null.
    try testing.expect(mon.parseBuffered() == null);
    try testing.expectEqual(mon.buffer_len, mon.iter_offset);
}

test "parseBuffered returns null when buffer only contains non-NEWLINK" {
    var mon: LinkMonitor = .{ .fd = -1 };
    mon.buffer_len = writeTestNewLink(&mon.buffer, rtnetlink.Type.DELLINK, 5, null);
    mon.iter_offset = 0;
    try testing.expect(mon.parseBuffered() == null);
}

test "monitor opens subscribed to RTMGRP_LINK" {
    var mon = LinkMonitor.open(rtnetlink.RTMGRP.LINK) catch |err| {
        // In some sandboxes AF_NETLINK is blocked; don't fail the suite.
        if (err == Error.SocketCreate or err == Error.SocketBind) {
            return error.SkipZigTest;
        }
        return err;
    };
    defer mon.close();
    try testing.expect(mon.fd >= 0);
}

test "monitor opens with no groups (unsubscribed)" {
    var mon = LinkMonitor.open(0) catch return error.SkipZigTest;
    defer mon.close();
    try testing.expect(mon.fd >= 0);
}

test "monitor next times out on idle feed" {
    var mon = LinkMonitor.open(rtnetlink.RTMGRP.LINK) catch return error.SkipZigTest;
    defer mon.close();
    // 30ms is long enough to avoid false positives from spurious kernel
    // events on a quiet test host, short enough to keep the suite fast.
    try testing.expectError(Error.Timeout, mon.next(30));
}

test "monitor waitCarrier times out when ifindex never reports up" {
    var mon = LinkMonitor.open(rtnetlink.RTMGRP.LINK) catch return error.SkipZigTest;
    defer mon.close();
    // ifindex 0xFFFF_FFFE won't exist, so waitCarrier must hit the deadline.
    try testing.expectError(Error.Timeout, mon.waitCarrier(0xFFFF_FFFE, 40));
}

test "two monitors can coexist on the same groups" {
    var a = LinkMonitor.open(rtnetlink.RTMGRP.LINK) catch return error.SkipZigTest;
    defer a.close();
    var b = LinkMonitor.open(rtnetlink.RTMGRP.LINK) catch return error.SkipZigTest;
    defer b.close();
    try testing.expect(a.fd != b.fd);
}
