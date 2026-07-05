#!/usr/bin/env python3
"""bridge - show / manipulate bridge addresses and devices"""

import argparse
import os
import struct
import sys


def read_file(path: str) -> str:
    try:
        with open(path) as handle:
            return handle.read().strip()
    except OSError:
        return ''


def is_bridge(iface: str) -> bool:
    return os.path.isdir(f'/sys/class/net/{iface}/bridge')


def bridges() -> list:
    try:
        return [i for i in os.listdir('/sys/class/net') if is_bridge(i)]
    except OSError:
        return []


def format_mac(mac_bytes: bytes) -> str:
    return ':'.join(f'{b:02x}' for b in mac_bytes)


def fdb_show(args) -> int:
    for bridge_name in bridges():
        if args.dev and bridge_name != args.dev:
            continue
        brforward = f'/sys/class/net/{bridge_name}/brforward'
        try:
            with open(brforward, 'rb') as handle:
                # struct __fdb_entry in kernel is 16 bytes on most configs
                entry_size = 16
                while True:
                    chunk = handle.read(entry_size)
                    if len(chunk) < entry_size:
                        break
                    # First 6 bytes are the MAC address on little-endian
                    mac = chunk[:6]
                    print(f'{format_mac(mac)} dev {bridge_name} vlan 1 master {bridge_name} permanent')
        except OSError:
            # Fallback: show bridge port MAC addresses
            brif_dir = f'/sys/class/net/{bridge_name}/brif'
            try:
                for port in os.listdir(brif_dir):
                    addr = read_file(f'{brif_dir}/{port}/address')
                    if addr:
                        print(f'{addr} dev {port} master {bridge_name} permanent')
            except OSError:
                continue
    return 0


def link_show(args) -> int:
    for bridge_name in bridges():
        if args.dev and bridge_name != args.dev:
            continue
        brif_dir = f'/sys/class/net/{bridge_name}/brif'
        try:
            for port in sorted(os.listdir(brif_dir)):
                state = read_file(f'{brif_dir}/{port}/operstate')
                addr = read_file(f'{brif_dir}/{port}/address')
                print(f'{port}: master {bridge_name} state {state.upper()}')
                print(f'    link/{addr}')
        except OSError:
            continue
    return 0


def mdb_show(args) -> int:
    for bridge_name in bridges():
        if args.dev and bridge_name != args.dev:
            continue
        mdb_path = f'/sys/class/net/{bridge_name}/brmulticast'
        try:
            with open(mdb_path) as handle:
                for line in handle:
                    print(line.strip())
        except OSError:
            print(f'bridge: {bridge_name} has no multicast database', file=sys.stderr)
    return 0


def monitor_with_bcc() -> int:
    try:
        from bcc import BPF
    except ImportError:
        print('bridge: BCC is required for monitor mode', file=sys.stderr)
        return 1

    program = '''
    #include <uapi/linux/ptrace.h>

    struct event {
        u8 addr[6];
        u16 vid;
        char dev[16];
    };

    BPF_PERF_OUTPUT(events);

    TRACEPOINT_PROBE(bridge, br_fdb_add) {
        struct event ev = {};
        ev.addr[0] = args->addr[0];
        ev.addr[1] = args->addr[1];
        ev.addr[2] = args->addr[2];
        ev.addr[3] = args->addr[3];
        ev.addr[4] = args->addr[4];
        ev.addr[5] = args->addr[5];
        ev.vid = args->vid;
        u32 dev_off = 0;
        bpf_probe_read(&dev_off, sizeof(dev_off), (char *)args + 12);
        char *dev = (char *)args + (dev_off & 0xFFFF);
        bpf_probe_read_str(&ev.dev, sizeof(ev.dev), dev);
        events.perf_submit(args, &ev, sizeof(ev));
        return 0;
    }
    '''

    b = BPF(text=program)

    def print_event(cpu, data, size):
        event = b['events'].event(data)
        dev = event.dev.decode('utf-8', 'replace').strip('\x00')
        mac = format_mac(bytes(event.addr))
        print(f'[FDB] dev={dev} mac={mac} vlan={event.vid}')

    print('Monitoring bridge FDB events (Ctrl-C to stop)...')
    b['events'].open_perf_buffer(print_event)
    while True:
        try:
            b.perf_buffer_poll()
        except KeyboardInterrupt:
            break
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        prog='bridge',
        description='show / manipulate bridge addresses and devices',
    )
    subparsers = parser.add_subparsers(dest='object')

    fdb = subparsers.add_parser('fdb', help='forwarding database')
    fdb.add_argument('action', nargs='?', default='show', choices=['show'])
    fdb.add_argument('dev', nargs='?')

    link = subparsers.add_parser('link', help='bridge port')
    link.add_argument('action', nargs='?', default='show', choices=['show'])
    link.add_argument('dev', nargs='?')

    mdb = subparsers.add_parser('mdb', help='multicast database')
    mdb.add_argument('action', nargs='?', default='show', choices=['show'])
    mdb.add_argument('dev', nargs='?')

    monitor = subparsers.add_parser('monitor', help='monitor bridge events with eBPF')

    args = parser.parse_args()

    if args.object == 'fdb':
        return fdb_show(args)
    if args.object == 'link':
        return link_show(args)
    if args.object == 'mdb':
        return mdb_show(args)
    if args.object == 'monitor':
        return monitor_with_bcc()

    parser.print_help()
    return 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(0)
