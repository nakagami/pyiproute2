# pyiproute2

A Python port of [iproute2](https://github.com/iproute2/iproute2) commands using [BCC](https://github.com/iovisor/bcc) for eBPF-based network tracing.

## Installation

```
pip install iproute2
```

## Commands

| Command  | Description |
|----------|-------------|
| `ip`     | Network configuration and monitoring |
| `ss`     | Socket statistics |
| `tc`     | Traffic control |
| `bridge` | Ethernet bridge administration |

## Implemented Subcommands

### ip

- `ip link show` - Display network interfaces
- `ip addr show` - Display IP addresses
- `ip route show` - Display routing table
- `ip neigh show` - Display neighbor table (ARP/NDP)
- `ip monitor` - Monitor network events with eBPF

### ss

- `ss` - Display socket statistics
- `ss -t` - TCP sockets
- `ss -u` - UDP sockets
- `ss -l` - Listening sockets
- `ss -p` - Show processes
- `ss -m` - Monitor socket events with eBPF

### tc

- `tc qdisc show` - Display queuing disciplines
- `tc filter show` - Display traffic filters
- `tc class show` - Display traffic classes
- `tc monitor` - Monitor qdisc events with eBPF

### bridge

- `bridge link show` - Display bridge ports
- `bridge fdb show` - Display forwarding database
- `bridge mdb show` - Display multicast database
- `bridge monitor` - Monitor bridge events with eBPF

## Requirements

- Linux kernel with eBPF support
- BCC (BPF Compiler Collection)
- Root privileges for eBPF-based monitoring

## License

See [LICENSE](LICENSE).
