# Claude Code Instructions for nlz

A minimal rtnetlink library for Zig, designed for network interface configuration in init systems and DHCP clients.

## Project Overview

- **Language**: Zig 0.17.0+
- **Target**: Linux only (uses netlink sockets)
- **Purpose**: Network interface, address, and route configuration via netlink

## Build Commands

```bash
zig build test    # Run all tests
```

## Architecture

### Modules

| Module | Purpose |
|--------|---------|
| `root.zig` | Public API exports |
| `socket.zig` | Netlink socket and high-level operations |
| `message.zig` | Generic netlink message/attribute parsing |
| `rtnetlink.zig` | Protocol constants (RTM_*, AF_*, IFF_*, etc.) |
| `link.zig` | Interface (link) message parsing/building |
| `address.zig` | IP address message parsing/building |
| `route.zig` | Route message parsing/building |

### Design Principles

1. **Minimal scope**: Only implement commonly needed operations
2. **No allocations in parsing**: Message structures reference input buffer slices
3. **Explicit allocator passing**: Socket operations require an allocator
4. **Builders for requests**: Use `*MessageBuilder` types to construct requests

## Code Style

### Formatting

- Use `zig fmt` on code before committing

### Comments

- Comments should explain "why", not "what"
- Avoid placeholder comments when removing code
- Keep commentary technical and concise

### Memory Management

- Iterators own their response data and must be `deinit()`'d
- Parsed messages reference slices into the response buffer
- Use `errdefer` for cleanup on error paths

### Error Handling

- Return explicit error unions
- `Error.NetlinkError` for kernel errors (no errno details currently)
- Socket operations can fail with `SocketCreate`, `Send`, `Receive`, etc.

### Testing

- Unit tests use constructed byte arrays to simulate netlink messages
- Tests verify struct sizes match kernel definitions
- Socket tests require CAP_NET_ADMIN (run as root)

## Adding Features

When adding new functionality:

1. Keep scope minimal - only add commonly needed operations
2. Add constants to `rtnetlink.zig` if needed
3. Add message parsing to the appropriate module
4. Add builder methods for constructing requests
5. Add high-level Socket methods
6. Add unit tests with constructed byte arrays

## Reference

- Linux kernel: `include/uapi/linux/rtnetlink.h`
- Linux kernel: `include/uapi/linux/if_link.h`
- Linux kernel: `include/uapi/linux/if_addr.h`
- iproute2 source for usage examples
