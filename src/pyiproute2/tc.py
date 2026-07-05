#!/usr/bin/env python3
"""tc - show / manipulate traffic control settings"""

import argparse
import os
import socket
import struct
import sys

RTM_GETQDISC = 0x26
RTM_NEWQDISC = 0x24
NLMSG_DONE = 0x3
NLM_F_REQUEST = 0x1
NLM_F_DUMP = 0x300
AF_UNSPEC = 0
NETLINK_ROUTE = 0

TCA_KIND = 1


def read_file(path: str) -> str:
    try:
        with open(path) as handle:
            return handle.read().strip()
    except OSError:
        return ''


def parse_rtattr(data: bytes, offset: int) -> dict:
    attrs = {}
    while offset < len(data):
        if offset + 4 > len(data):
            break
        rta_len, rta_type = struct.unpack_from('HH', data, offset)
        if rta_len < 4:
            break
        payload_len = rta_len - 4
        payload = data[offset + 4:offset + 4 + payload_len]
        # align to 4 bytes
        rta_len = (rta_len + 3) & ~3
        attrs[rta_type] = payload
        offset += rta_len
    return attrs


def qdisc_show_netlink() -> dict:
    """Return {ifindex: kind} by querying netlink RTM_GETQDISC."""
    result = {}
    sock = socket.socket(socket.AF_NETLINK, socket.SOCK_DGRAM, NETLINK_ROUTE)
    try:
        seq = 1
        tcmsg = struct.pack('BBHI III', AF_UNSPEC, 0, 0, 0, 0, 0, 0)
        nlmsg_len = 16 + len(tcmsg)
        nlmsg = struct.pack('IHHII', nlmsg_len, RTM_GETQDISC, NLM_F_REQUEST | NLM_F_DUMP, seq, 0)
        sock.send(nlmsg + tcmsg)

        buf = b''
        while True:
            chunk = sock.recv(8192)
            buf += chunk
            if len(chunk) < 8192:
                break

        offset = 0
        while offset + 16 <= len(buf):
            nlmsg_len, nlmsg_type, nlmsg_flags, nlmsg_seq, nlmsg_pid = struct.unpack_from('IHHII', buf, offset)
            if nlmsg_type == NLMSG_DONE:
                break
            if nlmsg_type == RTM_NEWQDISC:
                tcmsg_start = offset + 16
                if tcmsg_start + 20 <= len(buf):
                    tcm_family, _, _, tcm_ifindex, tcm_handle, tcm_parent, tcm_info = struct.unpack_from(
                        'BBHIIII', buf, tcmsg_start
                    )
                    attrs = parse_rtattr(buf, tcmsg_start + 20)
                    kind = attrs.get(TCA_KIND, b'').split(b'\x00', 1)[0].decode('utf-8', 'replace')
                    if kind and tcm_ifindex:
                        result[tcm_ifindex] = kind
            offset += nlmsg_len
            offset = (offset + 3) & ~3
    except OSError:
        pass
    finally:
        sock.close()
    return result


def build_ifindex_to_name() -> dict:
    mapping = {}
    try:
        for iface in os.listdir('/sys/class/net'):
            try:
                with open(f'/sys/class/net/{iface}/ifindex') as handle:
                    mapping[int(handle.read().strip())] = iface
            except (OSError, ValueError):
                continue
    except OSError:
        pass
    return mapping


def qdisc_show(args) -> int:
    ifindex_to_name = build_ifindex_to_name()
    qdiscs = qdisc_show_netlink()

    if not qdiscs:
        # Fallback to sysfs if netlink fails
        try:
            interfaces = sorted(os.listdir('/sys/class/net'))
        except OSError as exc:
            print(f'tc: {exc}', file=sys.stderr)
            return 1
        for iface in interfaces:
            if args.dev and iface != args.dev:
                continue
            qdisc = read_file(f'/sys/class/net/{iface}/qdisc')
            if not qdisc:
                qdisc = 'noqueue' if iface == 'lo' else 'pfifo_fast'
            print(f'qdisc {qdisc} 0: dev {iface} root refcnt 0')
        return 0

    for ifindex, kind in sorted(qdiscs.items()):
        iface = ifindex_to_name.get(ifindex, str(ifindex))
        if args.dev and iface != args.dev:
            continue
        print(f'qdisc {kind} 0: dev {iface} root refcnt 0')
    return 0


def filter_show(args) -> int:
    print('tc: filter show not yet implemented', file=sys.stderr)
    return 0


def class_show(args) -> int:
    print('tc: class show not yet implemented', file=sys.stderr)
    return 0


def monitor_with_bcc() -> int:
    try:
        from bcc import BPF
    except ImportError:
        print('tc: BCC is required for monitor mode', file=sys.stderr)
        return 1

    program = '''
    #include <uapi/linux/ptrace.h>

    struct event {
        int ifindex;
        u32 handle;
        u32 parent;
    };

    BPF_PERF_OUTPUT(events);

    TRACEPOINT_PROBE(qdisc, qdisc_enqueue) {
        struct event ev = {};
        ev.ifindex = args->ifindex;
        ev.handle = args->handle;
        ev.parent = args->parent;
        events.perf_submit(args, &ev, sizeof(ev));
        return 0;
    }
    '''

    b = BPF(text=program)
    ifindex_to_name = build_ifindex_to_name()

    def print_event(cpu, data, size):
        event = b['events'].event(data)
        name = ifindex_to_name.get(event.ifindex, str(event.ifindex))
        print(f'[QDISC] dev={name} handle=0x{event.handle:x} parent=0x{event.parent:x}')

    print('Monitoring qdisc enqueue events (Ctrl-C to stop)...')
    b['events'].open_perf_buffer(print_event)
    while True:
        try:
            b.perf_buffer_poll()
        except KeyboardInterrupt:
            break
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        prog='tc',
        description='show / manipulate traffic control settings',
    )
    subparsers = parser.add_subparsers(dest='object')

    qdisc = subparsers.add_parser('qdisc', help='queuing discipline')
    qdisc.add_argument('action', nargs='?', default='show', choices=['show'])
    qdisc.add_argument('dev', nargs='?')

    filter_parser = subparsers.add_parser('filter', help='traffic filter')
    filter_parser.add_argument('action', nargs='?', default='show', choices=['show'])
    filter_parser.add_argument('dev', nargs='?')

    class_parser = subparsers.add_parser('class', help='traffic class')
    class_parser.add_argument('action', nargs='?', default='show', choices=['show'])
    class_parser.add_argument('dev', nargs='?')

    monitor = subparsers.add_parser('monitor', help='monitor tc events with eBPF')

    args = parser.parse_args()

    if args.object == 'qdisc':
        return qdisc_show(args)
    if args.object == 'filter':
        return filter_show(args)
    if args.object == 'class':
        return class_show(args)
    if args.object == 'monitor':
        return monitor_with_bcc()

    parser.print_help()
    return 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(0)
