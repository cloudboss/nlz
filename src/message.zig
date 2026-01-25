//! Generic netlink message structures and constants.
//!
//! This module provides the low-level building blocks for netlink communication:
//! - `Header`: The 16-byte netlink message header (struct nlmsghdr)
//! - `Attribute`: The 4-byte attribute header (struct rtattr)
//! - `Message`: A complete netlink message with header and payload
//! - Iterators for parsing multiple messages and attributes

const std = @import("std");
const mem = std.mem;

/// Netlink message header (struct nlmsghdr).
///
/// Every netlink message starts with this 16-byte header containing:
/// - `len`: Total message length including header
/// - `type`: Message type (protocol-specific or generic like ERROR/DONE)
/// - `flags`: Request/response flags
/// - `seq`: Sequence number for request/response matching
/// - `pid`: Port ID (usually process ID)
pub const Header = extern struct {
    /// Total length of message including header.
    len: u32,
    /// Message type (RTM_NEWLINK, RTM_GETADDR, etc. or NLMSG_ERROR/DONE).
    type: u16,
    /// Message flags (NLM_F_REQUEST, NLM_F_DUMP, etc.).
    flags: u16,
    /// Sequence number for matching requests to responses.
    seq: u32,
    /// Sender port ID.
    pid: u32,

    pub const SIZE: usize = 16;

    comptime {
        std.debug.assert(@sizeOf(Header) == SIZE);
    }

    /// Parse a header from raw bytes.
    pub fn fromBytes(bytes: []const u8) ?Header {
        if (bytes.len < SIZE) return null;
        return mem.bytesAsValue(Header, bytes[0..SIZE]).*;
    }

    /// Get the raw bytes of the header.
    pub fn toBytes(self: *const Header) *const [SIZE]u8 {
        return @ptrCast(self);
    }
};

/// Generic netlink message types (NLMSG_*).
pub const Type = struct {
    /// No operation, for padding.
    pub const NOOP: u16 = 1;
    /// Error response or ACK.
    pub const ERROR: u16 = 2;
    /// End of multipart message.
    pub const DONE: u16 = 3;
    /// Data lost due to buffer overflow.
    pub const OVERRUN: u16 = 4;
};

/// Netlink message flags (NLM_F_*).
pub const Flags = struct {
    /// This is a request message.
    pub const REQUEST: u16 = 0x01;
    /// Multipart message, more messages follow.
    pub const MULTI: u16 = 0x02;
    /// Request acknowledgement.
    pub const ACK: u16 = 0x04;
    /// Echo this request back.
    pub const ECHO: u16 = 0x08;
    /// Dump was interrupted.
    pub const DUMP_INTR: u16 = 0x10;
    /// Dump was filtered.
    pub const DUMP_FILTERED: u16 = 0x20;

    // Modifiers to GET request
    /// Return complete table instead of single entry.
    pub const ROOT: u16 = 0x100;
    /// Return all matching entries.
    pub const MATCH: u16 = 0x200;
    /// Atomic operation (deprecated).
    pub const ATOMIC: u16 = 0x400;
    /// Dump request (ROOT | MATCH).
    pub const DUMP: u16 = ROOT | MATCH;

    // Modifiers to NEW request
    /// Replace existing entry.
    pub const REPLACE: u16 = 0x100;
    /// Don't replace if exists.
    pub const EXCL: u16 = 0x200;
    /// Create if doesn't exist.
    pub const CREATE: u16 = 0x400;
    /// Append to end of list.
    pub const APPEND: u16 = 0x800;
};

/// Netlink error message (struct nlmsgerr).
///
/// Returned when a request fails or as an ACK (with err=0).
pub const ErrorMessage = extern struct {
    /// Negative errno value, or 0 for ACK.
    err: i32,
    /// Header of the message that caused the error.
    msg: Header,

    pub const SIZE: usize = 20;

    comptime {
        std.debug.assert(@sizeOf(ErrorMessage) == SIZE);
    }

    /// Parse an error message from raw bytes.
    pub fn fromBytes(bytes: []const u8) ?ErrorMessage {
        if (bytes.len < SIZE) return null;
        return mem.bytesAsValue(ErrorMessage, bytes[0..SIZE]).*;
    }
};

/// Netlink attribute header (struct rtattr/nlattr).
///
/// Attributes follow the protocol-specific header and contain typed data.
/// Each attribute has a 4-byte header with length and type, followed by payload.
pub const Attribute = extern struct {
    /// Total length including header.
    len: u16,
    /// Attribute type (protocol-specific).
    type: u16,

    pub const HEADER_SIZE: usize = 4;

    comptime {
        std.debug.assert(@sizeOf(Attribute) == HEADER_SIZE);
    }

    /// Parse an attribute header from raw bytes.
    pub fn fromBytes(bytes: []const u8) ?Attribute {
        if (bytes.len < HEADER_SIZE) return null;
        return mem.bytesAsValue(Attribute, bytes[0..HEADER_SIZE]).*;
    }

    /// Get the payload bytes (after the header).
    pub fn payload(self: Attribute, bytes: []const u8) ?[]const u8 {
        if (bytes.len < self.len) return null;
        if (self.len < HEADER_SIZE) return null;
        return bytes[HEADER_SIZE..self.len];
    }

    /// Get the payload interpreted as a specific type.
    pub fn payloadAs(self: Attribute, comptime T: type, bytes: []const u8) ?T {
        const data = self.payload(bytes) orelse return null;
        if (data.len < @sizeOf(T)) return null;
        return mem.bytesAsValue(T, data[0..@sizeOf(T)]).*;
    }

    /// Get the payload interpreted as a slice of a specific type.
    pub fn payloadAsSlice(self: Attribute, comptime T: type, bytes: []const u8) ?[]const T {
        const data = self.payload(bytes) orelse return null;
        const count = data.len / @sizeOf(T);
        if (count == 0) return null;
        const ptr: [*]const T = @ptrCast(@alignCast(data.ptr));
        return ptr[0..count];
    }
};

/// Align a length to 4-byte boundary (NLMSG_ALIGN).
///
/// Netlink messages and attributes are padded to 4-byte alignment.
pub fn align4(len: usize) usize {
    return (len + 3) & ~@as(usize, 3);
}

/// A complete netlink message with header and payload.
pub const Message = struct {
    /// The message header.
    header: Header,
    /// The message payload (after the header).
    payload: []const u8,

    /// Parse a message from raw bytes.
    pub fn fromBytes(bytes: []const u8) ?Message {
        const header = Header.fromBytes(bytes) orelse return null;
        if (header.len < Header.SIZE) return null;
        if (bytes.len < header.len) return null;
        return .{
            .header = header,
            .payload = bytes[Header.SIZE..header.len],
        };
    }

    /// Check if this is an error message (NLMSG_ERROR).
    pub fn isError(self: Message) bool {
        return self.header.type == Type.ERROR;
    }

    /// Check if this is the end of a multipart dump (NLMSG_DONE).
    pub fn isDone(self: Message) bool {
        return self.header.type == Type.DONE;
    }

    /// Check if more messages follow (NLM_F_MULTI).
    pub fn isMulti(self: Message) bool {
        return self.header.flags & Flags.MULTI != 0;
    }

    /// Get the error code if this is an error message.
    /// Returns negative errno on error, 0 for ACK, null if not an error message.
    pub fn getError(self: Message) ?i32 {
        if (!self.isError()) return null;
        const err_msg = ErrorMessage.fromBytes(self.payload) orelse return null;
        return err_msg.err;
    }
};

/// Iterator over netlink messages in a buffer.
///
/// Handles the 4-byte alignment between messages.
pub const MessageIterator = struct {
    buffer: []const u8,
    offset: usize,

    /// Create an iterator over messages in a buffer.
    pub fn init(buffer: []const u8) MessageIterator {
        return .{ .buffer = buffer, .offset = 0 };
    }

    /// Get the next message, or null if no more messages.
    pub fn next(self: *MessageIterator) ?Message {
        if (self.offset >= self.buffer.len) return null;
        const remaining = self.buffer[self.offset..];
        const msg = Message.fromBytes(remaining) orelse return null;
        self.offset += align4(msg.header.len);
        return msg;
    }
};

/// Iterator over attributes in a payload.
///
/// Handles the 4-byte alignment between attributes.
pub const AttributeIterator = struct {
    buffer: []const u8,
    offset: usize,

    /// Create an iterator over attributes in a buffer.
    pub fn init(buffer: []const u8) AttributeIterator {
        return .{ .buffer = buffer, .offset = 0 };
    }

    /// Get the next attribute with its data, or null if no more attributes.
    pub fn next(self: *AttributeIterator) ?struct { attr: Attribute, data: []const u8 } {
        if (self.offset >= self.buffer.len) return null;
        const remaining = self.buffer[self.offset..];
        const attr = Attribute.fromBytes(remaining) orelse return null;
        if (attr.len < Attribute.HEADER_SIZE) return null;
        if (remaining.len < attr.len) return null;
        self.offset += align4(attr.len);
        return .{ .attr = attr, .data = remaining[0..attr.len] };
    }
};

// =============================================================================
// Tests
// =============================================================================

test "header size" {
    try std.testing.expectEqual(@as(usize, 16), Header.SIZE);
}

test "error message size" {
    try std.testing.expectEqual(@as(usize, 20), ErrorMessage.SIZE);
}

test "attribute header size" {
    try std.testing.expectEqual(@as(usize, 4), Attribute.HEADER_SIZE);
}

test "align4" {
    try std.testing.expectEqual(@as(usize, 0), align4(0));
    try std.testing.expectEqual(@as(usize, 4), align4(1));
    try std.testing.expectEqual(@as(usize, 4), align4(2));
    try std.testing.expectEqual(@as(usize, 4), align4(3));
    try std.testing.expectEqual(@as(usize, 4), align4(4));
    try std.testing.expectEqual(@as(usize, 8), align4(5));
    try std.testing.expectEqual(@as(usize, 16), align4(16));
    try std.testing.expectEqual(@as(usize, 20), align4(17));
}

test "header from bytes" {
    const bytes = [_]u8{
        0x20, 0x00, 0x00, 0x00, // len = 32
        0x10, 0x00, // type = 16 (RTM_NEWLINK)
        0x01, 0x03, // flags = 0x0301
        0x01, 0x00, 0x00, 0x00, // seq = 1
        0x00, 0x10, 0x00, 0x00, // pid = 4096
    };
    const header = Header.fromBytes(&bytes).?;
    try std.testing.expectEqual(@as(u32, 32), header.len);
    try std.testing.expectEqual(@as(u16, 16), header.type);
    try std.testing.expectEqual(@as(u16, 0x0301), header.flags);
    try std.testing.expectEqual(@as(u32, 1), header.seq);
    try std.testing.expectEqual(@as(u32, 4096), header.pid);
}

test "header from bytes too short" {
    const bytes = [_]u8{ 0x20, 0x00, 0x00, 0x00, 0x10, 0x00 };
    try std.testing.expect(Header.fromBytes(&bytes) == null);
}

test "message from bytes" {
    var bytes: [32]u8 = undefined;
    // Header
    bytes[0] = 0x20; // len = 32
    bytes[1] = 0x00;
    bytes[2] = 0x00;
    bytes[3] = 0x00;
    bytes[4] = 0x10; // type = 16
    bytes[5] = 0x00;
    bytes[6] = 0x01; // flags = 1
    bytes[7] = 0x00;
    @memset(bytes[8..16], 0); // seq, pid
    @memset(bytes[16..32], 0xAA); // payload

    const msg = Message.fromBytes(&bytes).?;
    try std.testing.expectEqual(@as(u32, 32), msg.header.len);
    try std.testing.expectEqual(@as(usize, 16), msg.payload.len);
    try std.testing.expectEqual(@as(u8, 0xAA), msg.payload[0]);
}

test "message iterator" {
    // Two messages: 20 bytes and 24 bytes (padded to 24)
    var bytes: [48]u8 = undefined;
    @memset(&bytes, 0);

    // First message: len=20
    bytes[0] = 20;
    bytes[4] = 16; // type

    // Second message at offset 20 (aligned): len=24
    bytes[20] = 24;
    bytes[24] = 17; // type

    var iter = MessageIterator.init(&bytes);

    const msg1 = iter.next().?;
    try std.testing.expectEqual(@as(u32, 20), msg1.header.len);
    try std.testing.expectEqual(@as(u16, 16), msg1.header.type);

    const msg2 = iter.next().?;
    try std.testing.expectEqual(@as(u32, 24), msg2.header.len);
    try std.testing.expectEqual(@as(u16, 17), msg2.header.type);

    try std.testing.expect(iter.next() == null);
}

test "attribute payload" {
    var bytes: [12]u8 = undefined;
    bytes[0] = 12; // len = 12
    bytes[1] = 0;
    bytes[2] = 3; // type = 3 (IFLA_IFNAME)
    bytes[3] = 0;
    @memcpy(bytes[4..12], "eth0\x00\x00\x00\x00");

    const attr = Attribute.fromBytes(&bytes).?;
    try std.testing.expectEqual(@as(u16, 12), attr.len);
    try std.testing.expectEqual(@as(u16, 3), attr.type);

    const payload = attr.payload(&bytes).?;
    try std.testing.expectEqual(@as(usize, 8), payload.len);
    try std.testing.expectEqualStrings("eth0", mem.sliceTo(payload, 0));
}

test "attribute payloadAs u32" {
    var bytes: [8]u8 = undefined;
    bytes[0] = 8; // len = 8
    bytes[1] = 0;
    bytes[2] = 4; // type = 4 (IFLA_MTU)
    bytes[3] = 0;
    bytes[4] = 0xDC; // 1500 in little-endian
    bytes[5] = 0x05;
    bytes[6] = 0x00;
    bytes[7] = 0x00;

    const attr = Attribute.fromBytes(&bytes).?;
    const mtu = attr.payloadAs(u32, &bytes).?;
    try std.testing.expectEqual(@as(u32, 1500), mtu);
}

test "attribute iterator" {
    // Two attributes: 8 bytes and 12 bytes (second padded to 12)
    var bytes: [20]u8 = undefined;
    @memset(&bytes, 0);

    // First attr: len=8, type=4
    bytes[0] = 8;
    bytes[2] = 4;

    // Second attr at offset 8: len=10, type=3
    bytes[8] = 10;
    bytes[10] = 3;

    var iter = AttributeIterator.init(&bytes);

    const item1 = iter.next().?;
    try std.testing.expectEqual(@as(u16, 8), item1.attr.len);
    try std.testing.expectEqual(@as(u16, 4), item1.attr.type);

    const item2 = iter.next().?;
    try std.testing.expectEqual(@as(u16, 10), item2.attr.len);
    try std.testing.expectEqual(@as(u16, 3), item2.attr.type);

    try std.testing.expect(iter.next() == null);
}

test "error message ACK" {
    var bytes: [36]u8 = undefined;
    @memset(&bytes, 0);

    // Outer header
    bytes[0] = 36; // len
    bytes[4] = Type.ERROR; // type = NLMSG_ERROR

    // Error payload: err=0 (ACK), followed by original header
    // err is at bytes[16..20], already 0
    // Original header at bytes[20..36]
    bytes[20] = 20; // original len

    const msg = Message.fromBytes(&bytes).?;
    try std.testing.expect(msg.isError());
    try std.testing.expectEqual(@as(i32, 0), msg.getError().?);
}

test "message flags" {
    var bytes: [20]u8 = undefined;
    @memset(&bytes, 0);
    bytes[0] = 20; // len
    bytes[6] = @truncate(Flags.MULTI); // flags

    const msg = Message.fromBytes(&bytes).?;
    try std.testing.expect(msg.isMulti());
    try std.testing.expect(!msg.isDone());
    try std.testing.expect(!msg.isError());
}

test "done message" {
    var bytes: [20]u8 = undefined;
    @memset(&bytes, 0);
    bytes[0] = 20; // len
    bytes[4] = Type.DONE; // type

    const msg = Message.fromBytes(&bytes).?;
    try std.testing.expect(msg.isDone());
}

test "message from bytes too short" {
    const bytes = [_]u8{ 0x10, 0x00, 0x00, 0x00 }; // Only 4 bytes, need 16 minimum
    try std.testing.expect(Message.fromBytes(&bytes) == null);
}

test "message with length smaller than header" {
    var bytes: [16]u8 = undefined;
    @memset(&bytes, 0);
    bytes[0] = 8; // len = 8, but header is 16 bytes
    try std.testing.expect(Message.fromBytes(&bytes) == null);
}

test "message with length exceeding buffer" {
    var bytes: [16]u8 = undefined;
    @memset(&bytes, 0);
    bytes[0] = 32; // len = 32, but buffer is only 16
    try std.testing.expect(Message.fromBytes(&bytes) == null);
}

test "attribute with zero length" {
    var bytes: [4]u8 = undefined;
    bytes[0] = 0; // len = 0
    bytes[1] = 0;
    bytes[2] = 1; // type
    bytes[3] = 0;

    const attr = Attribute.fromBytes(&bytes).?;
    // payload should return null for len < HEADER_SIZE
    try std.testing.expect(attr.payload(&bytes) == null);
}

test "attribute with length less than header" {
    var bytes: [4]u8 = undefined;
    bytes[0] = 2; // len = 2 (less than 4-byte header)
    bytes[1] = 0;
    bytes[2] = 1;
    bytes[3] = 0;

    const attr = Attribute.fromBytes(&bytes).?;
    try std.testing.expect(attr.payload(&bytes) == null);
}

test "attribute payload exceeds buffer" {
    var bytes: [8]u8 = undefined;
    bytes[0] = 16; // len = 16, but buffer is only 8
    bytes[1] = 0;
    bytes[2] = 1;
    bytes[3] = 0;

    const attr = Attribute.fromBytes(&bytes).?;
    try std.testing.expect(attr.payload(&bytes) == null);
}

test "attribute payloadAs with insufficient data" {
    var bytes: [6]u8 = undefined;
    bytes[0] = 6; // len = 6 (4 header + 2 payload)
    bytes[1] = 0;
    bytes[2] = 4; // type
    bytes[3] = 0;
    bytes[4] = 0xAB;
    bytes[5] = 0xCD;

    const attr = Attribute.fromBytes(&bytes).?;
    // Try to read as u32, but only 2 bytes available
    try std.testing.expect(attr.payloadAs(u32, &bytes) == null);
}

test "attribute payloadAsSlice empty" {
    var bytes: [4]u8 = undefined;
    bytes[0] = 4; // len = 4 (header only, no payload)
    bytes[1] = 0;
    bytes[2] = 1;
    bytes[3] = 0;

    const attr = Attribute.fromBytes(&bytes).?;
    // Empty payload cannot be interpreted as slice
    try std.testing.expect(attr.payloadAsSlice(u32, &bytes) == null);
}

test "error message with negative errno" {
    var bytes: [36]u8 = undefined;
    @memset(&bytes, 0);

    // Outer header
    bytes[0] = 36; // len
    bytes[4] = Type.ERROR; // type = NLMSG_ERROR

    // Error payload: err = -2 (ENOENT)
    bytes[16] = 0xFE; // -2 in little-endian two's complement
    bytes[17] = 0xFF;
    bytes[18] = 0xFF;
    bytes[19] = 0xFF;

    const msg = Message.fromBytes(&bytes).?;
    try std.testing.expect(msg.isError());
    try std.testing.expectEqual(@as(i32, -2), msg.getError().?);
}

test "getError on non-error message" {
    var bytes: [20]u8 = undefined;
    @memset(&bytes, 0);
    bytes[0] = 20; // len
    bytes[4] = 16; // type = RTM_NEWLINK (not ERROR)

    const msg = Message.fromBytes(&bytes).?;
    try std.testing.expect(!msg.isError());
    try std.testing.expect(msg.getError() == null);
}

test "message iterator with unaligned message" {
    // First message: 18 bytes (will be padded to 20)
    // Second message: 20 bytes
    var bytes: [40]u8 = undefined;
    @memset(&bytes, 0);

    bytes[0] = 18; // len = 18 (not aligned)
    bytes[4] = 16; // type

    // Second message at offset 20 (aligned from 18)
    bytes[20] = 20;
    bytes[24] = 17; // type

    var iter = MessageIterator.init(&bytes);

    const msg1 = iter.next().?;
    try std.testing.expectEqual(@as(u32, 18), msg1.header.len);

    const msg2 = iter.next().?;
    try std.testing.expectEqual(@as(u32, 20), msg2.header.len);

    try std.testing.expect(iter.next() == null);
}

test "attribute iterator stops at buffer end" {
    // Single attribute that exactly fills buffer
    var bytes: [8]u8 = undefined;
    bytes[0] = 8; // len = 8
    bytes[1] = 0;
    bytes[2] = 1; // type
    bytes[3] = 0;
    @memset(bytes[4..8], 0xAA);

    var iter = AttributeIterator.init(&bytes);

    const item = iter.next().?;
    try std.testing.expectEqual(@as(u16, 8), item.attr.len);

    // No more attributes
    try std.testing.expect(iter.next() == null);
}

test "header toBytes roundtrip" {
    const header = Header{
        .len = 32,
        .type = 16,
        .flags = 0x301,
        .seq = 42,
        .pid = 1234,
    };

    const bytes = header.toBytes();
    const parsed = Header.fromBytes(bytes).?;

    try std.testing.expectEqual(header.len, parsed.len);
    try std.testing.expectEqual(header.type, parsed.type);
    try std.testing.expectEqual(header.flags, parsed.flags);
    try std.testing.expectEqual(header.seq, parsed.seq);
    try std.testing.expectEqual(header.pid, parsed.pid);
}
