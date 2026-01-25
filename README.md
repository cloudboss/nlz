# nlz

A minimal rtnetlink library for Zig, providing network interface configuration via Linux netlink sockets.

## Features

- **Link operations**: List interfaces, bring up, rename
- **Address operations**: Add/delete IPv4/IPv6 addresses
- **Route operations**: Add/delete IPv4/IPv6 routes
- **Zero-copy parsing**: Message structures reference input buffers
- **No libc dependency**: Uses Zig's std.os.linux directly

## Installation

```bash
zig fetch --save git+https://github.com/cloudboss/nlz
```

Then in `build.zig`:

```zig
const nlz = b.dependency("nlz", .{
    .target = target,
    .optimize = optimize,
});
exe.root_module.addImport("nlz", nlz.module("nlz"));
```

## Usage

```zig
const std = @import("std");
const nlz = @import("nlz");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Open a netlink socket
    var socket = try nlz.Socket.open();
    defer socket.close();

    // List all network interfaces
    var links = try socket.getLinks(allocator);
    defer links.deinit();
    while (links.next()) |link| {
        std.debug.print("Interface: {s} (index={}, up={}, carrier={})\n", .{
            link.name orelse "unknown",
            link.ifindex(),
            link.isUp(),
            link.hasCarrier(),
        });
    }

    // Bring interface up (requires CAP_NET_ADMIN)
    try socket.setLinkUp(2, allocator);

    // Add an IPv4 address
    try socket.addAddressIPv4(2, .{ 192, 168, 1, 100 }, 24, allocator);

    // Add a default route
    try socket.addRouteIPv4(2, .{ 0, 0, 0, 0 }, .{ 192, 168, 1, 1 }, 0, allocator);

    // Delete an address
    try socket.delAddressIPv4(2, .{ 192, 168, 1, 100 }, 24, allocator);
}
```

## API Reference

### Socket

| Method | Description |
|--------|-------------|
| `open()` | Open a new rtnetlink socket |
| `close()` | Close the socket |
| `getLinks()` | List all network interfaces |
| `setLinkUp(ifindex)` | Bring an interface up |
| `setLinkName(ifindex, name)` | Rename an interface |
| `getAddresses(family)` | Get all addresses (AF_INET or AF_INET6) |
| `getAddressesFiltered(family, ifindex)` | Get addresses for a specific interface |
| `addAddressIPv4(ifindex, addr, prefix_len)` | Add an IPv4 address |
| `addAddressIPv6(ifindex, addr, prefix_len)` | Add an IPv6 address |
| `delAddressIPv4(ifindex, addr, prefix_len)` | Delete an IPv4 address |
| `delAddressIPv6(ifindex, addr, prefix_len)` | Delete an IPv6 address |
| `delAddress(addr_msg)` | Delete using an AddressMessage |
| `addRouteIPv4(ifindex, dst, gateway, prefix_len)` | Add an IPv4 route |
| `addRouteIPv6(ifindex, dst, gateway, prefix_len)` | Add an IPv6 route |
| `delRouteIPv4(ifindex, dst, prefix_len)` | Delete an IPv4 route |
| `delRouteIPv6(ifindex, dst, prefix_len)` | Delete an IPv6 route |

### LinkMessage

| Field/Method | Description |
|--------------|-------------|
| `name` | Interface name (e.g., "eth0") |
| `address` | MAC address bytes |
| `mtu` | Maximum transmission unit |
| `carrier` | Carrier status (1 = link detected) |
| `link_kind` | Virtual interface type |
| `ifindex()` | Get interface index |
| `isUp()` | Check if IFF_UP flag is set |
| `hasCarrier()` | Check if carrier is present |
| `isVirtual()` | Check if virtual interface |
| `getMacAddress()` | Get MAC as [6]u8 |

### AddressMessage

| Field/Method | Description |
|--------------|-------------|
| `address` | IP address bytes |
| `local` | Local address (point-to-point) |
| `broadcast` | Broadcast address |
| `ifindex()` | Get interface index |
| `prefixLen()` | Get prefix length (CIDR) |
| `family()` | Get address family |
| `isIPv4()` | Check if IPv4 |
| `isIPv6()` | Check if IPv6 |
| `getIPv4Address()` | Get as [4]u8 |
| `getIPv6Address()` | Get as [16]u8 |

### RouteMessage

| Field/Method | Description |
|--------------|-------------|
| `dst` | Destination address bytes |
| `gateway` | Gateway address bytes |
| `oif` | Output interface index |
| `family()` | Get address family |
| `dstLen()` | Get destination prefix length |
| `isDefaultRoute()` | Check if default route (prefix_len=0) |
| `getIPv4Dst()` | Get destination as [4]u8 |
| `getIPv4Gateway()` | Get gateway as [4]u8 |

## Requirements

- Linux kernel 2.6.14+ (netlink sockets)
- CAP_NET_ADMIN capability for modifying network configuration
- Zig 0.15.0+

## License

MIT
