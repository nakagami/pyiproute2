#!/usr/bin/env python3
"""ss - utility to investigate sockets"""

import argparse
import os
import socket
import struct
import sys
import time

TCP_STATES = {
    '00': 'UNKNOWN',
    '01': 'ESTAB',
    '02': 'SYN-SENT',
    '03': 'SYN-RECV',
    '04': 'FIN-WAIT-1',
    '05': 'FIN-WAIT-2',
    '06': 'TIME-WAIT',
    '07': 'CLOSE',
    '08': 'CLOSE-WAIT',
    '09': 'LAST-ACK',
    '0A': 'LISTEN',
    '0B': 'CLOSING',
    '0C': 'NEW-SYN-RECV',
}

UDP_STATE = 'UNCONN'


def hex_to_ipv4(text: str) -> str:
    addr = int(text, 16)
    return socket.inet_ntoa(struct.pack('<I', addr))


def hex_to_ipv6(text: str) -> str:
    addr = bytes.fromhex(text)
    # /proc/net/tcp6 stores addresses as four 32-bit words in network order
    # but each word is little-endian in the hex string.
    parts = []
    for i in range(0, 16, 4):
        parts.append(struct.unpack('>I', addr[i:i + 4][::-1])[0])
    return socket.inet_ntop(socket.AF_INET6, b''.join(struct.pack('>I', p) for p in parts))


def hex_to_port(text: str) -> int:
    return int(text, 16)


def format_address(ip: str, port: int, numeric: bool) -> str:
    if not numeric and port:
        try:
            service = socket.getservbyport(port)
            if ':' in ip:
                return f'[{ip}]:{service}'
            return f'{ip}:{service}'
        except OSError:
            pass
    if ':' in ip:
        return f'[{ip}]:{port}'
    return f'{ip}:{port}'


def build_inode_to_pid() -> dict:
    mapping: dict = {}
    try:
        for entry in os.listdir('/proc'):
            if not entry.isdigit():
                continue
            pid = int(entry)
            fd_dir = f'/proc/{entry}/fd'
            try:
                for fd in os.listdir(fd_dir):
                    try:
                        target = os.readlink(f'{fd_dir}/{fd}')
                        if target.startswith('socket:['):
                            inode = int(target[8:-1])
                            mapping[inode] = pid
                    except OSError:
                        continue
            except OSError:
                continue
    except OSError:
        pass
    return mapping


def pid_to_cmdline(pid: int) -> str:
    try:
        with open(f'/proc/{pid}/comm') as handle:
            return handle.read().strip()
    except OSError:
        return '?'


def read_proc_net(path: str, family: int) -> list:
    sockets = []
    try:
        with open(path) as handle:
            next(handle)  # skip header
            for line in handle:
                fields = line.split()
                if len(fields) < 10:
                    continue
                local = fields[1]
                remote = fields[2]
                state = fields[3]
                inode = int(fields[9])
                uid = int(fields[7]) if len(fields) > 7 else 0

                local_ip, local_port = local.rsplit(':', 1)
                remote_ip, remote_port = remote.rsplit(':', 1)

                if family == socket.AF_INET6:
                    local_ip = hex_to_ipv6(local_ip)
                    remote_ip = hex_to_ipv6(remote_ip)
                else:
                    local_ip = hex_to_ipv4(local_ip)
                    remote_ip = hex_to_ipv4(remote_ip)

                local_port = hex_to_port(local_port)
                remote_port = hex_to_port(remote_port)

                sockets.append({
                    'family': family,
                    'local_ip': local_ip,
                    'local_port': local_port,
                    'remote_ip': remote_ip,
                    'remote_port': remote_port,
                    'state': TCP_STATES.get(state.upper(), state),
                    'inode': inode,
                    'uid': uid,
                })
    except OSError:
        pass
    return sockets


def read_proc_net_udp(path: str, family: int) -> list:
    sockets = []
    try:
        with open(path) as handle:
            next(handle)
            for line in handle:
                fields = line.split()
                if len(fields) < 10:
                    continue
                local = fields[1]
                remote = fields[2]
                inode = int(fields[9])
                uid = int(fields[7]) if len(fields) > 7 else 0

                local_ip, local_port = local.rsplit(':', 1)
                remote_ip, remote_port = remote.rsplit(':', 1)

                if family == socket.AF_INET6:
                    local_ip = hex_to_ipv6(local_ip)
                    remote_ip = hex_to_ipv6(remote_ip)
                else:
                    local_ip = hex_to_ipv4(local_ip)
                    remote_ip = hex_to_ipv4(remote_ip)

                local_port = hex_to_port(local_port)
                remote_port = hex_to_port(remote_port)

                sockets.append({
                    'family': family,
                    'local_ip': local_ip,
                    'local_port': local_port,
                    'remote_ip': remote_ip,
                    'remote_port': remote_port,
                    'state': UDP_STATE,
                    'inode': inode,
                    'uid': uid,
                })
    except OSError:
        pass
    return sockets


def collect_sockets(tcp: bool, udp: bool, ipv4: bool, ipv6: bool) -> list:
    sockets = []
    if tcp:
        if ipv4:
            sockets.extend(read_proc_net('/proc/net/tcp', socket.AF_INET))
        if ipv6:
            sockets.extend(read_proc_net('/proc/net/tcp6', socket.AF_INET6))
    if udp:
        if ipv4:
            sockets.extend(read_proc_net_udp('/proc/net/udp', socket.AF_INET))
        if ipv6:
            sockets.extend(read_proc_net_udp('/proc/net/udp6', socket.AF_INET6))
    return sockets


def filter_sockets(sockets: list, listening: bool, all_sockets: bool, states: list) -> list:
    if states:
        return [s for s in sockets if s['state'] in states]
    if listening:
        return [s for s in sockets if s['state'] == 'LISTEN']
    if not all_sockets:
        return [s for s in sockets if s['state'] not in ('UNCONN', 'TIME-WAIT', 'CLOSE', 'LISTEN')]
    return sockets


def print_sockets(sockets: list, numeric: bool, show_processes: bool) -> None:
    if show_processes:
        inode_to_pid = build_inode_to_pid()
    else:
        inode_to_pid = {}

    print(f"{'Netid':<6} {'State':<12} {'Recv-Q':>7} {'Send-Q':>7} "
          f"{'Local Address:Port':<30} {'Peer Address:Port':<30}", end='')
    if show_processes:
        print(f" {'Process'}")
    else:
        print()

    for s in sockets:
        if s['family'] == socket.AF_INET6:
            netid = 'tcp' if s['state'] != UDP_STATE else 'udp'
        else:
            netid = 'tcp' if s['state'] != UDP_STATE else 'udp'
        local = format_address(s['local_ip'], s['local_port'], numeric)
        remote = format_address(s['remote_ip'], s['remote_port'], numeric)
        print(f"{netid:<6} {s['state']:<12} {0:>7} {0:>7} "
              f"{local:<30} {remote:<30}", end='')
        if show_processes:
            pid = inode_to_pid.get(s['inode'])
            if pid is not None:
                print(f" users:(({pid},{pid_to_cmdline(pid)}))")
            else:
                print()
        else:
            print()


TCP_STATE_NAMES = {
    1: 'ESTAB',
    2: 'SYN-SENT',
    3: 'SYN-RECV',
    4: 'FIN-WAIT-1',
    5: 'FIN-WAIT-2',
    6: 'TIME-WAIT',
    7: 'CLOSE',
    8: 'CLOSE-WAIT',
    9: 'LAST-ACK',
    10: 'LISTEN',
    11: 'CLOSING',
    12: 'NEW-SYN-RECV',
}


def monitor_with_bcc(tcp: bool, udp: bool) -> int:
    try:
        from bcc import BPF
    except ImportError:
        print('ss: BCC is required for monitor mode', file=sys.stderr)
        return 1

    program = '''
    #include <uapi/linux/ptrace.h>

    struct event {
        u32 pid;
        u16 family;
        u16 sport;
        u16 dport;
        u16 protocol;
        u32 oldstate;
        u32 newstate;
        u8 saddr[16];
        u8 daddr[16];
    };

    BPF_PERF_OUTPUT(events);

    static void copy_addr(u8 *dst, u8 *src, int len) {
        for (int i = 0; i < len; i++) {
            dst[i] = src[i];
        }
    }

    TRACEPOINT_PROBE(sock, inet_sock_set_state) {
        if (args->protocol != 6 && args->protocol != 132 && args->protocol != 262) {
            return 0;
        }
        struct event ev = {};
        ev.pid = bpf_get_current_pid_tgid() >> 32;
        ev.family = args->family;
        ev.sport = args->sport;
        ev.dport = args->dport;
        ev.protocol = args->protocol;
        ev.oldstate = args->oldstate;
        ev.newstate = args->newstate;
        if (args->family == 2) {
            copy_addr(ev.saddr, args->saddr, 4);
            copy_addr(ev.daddr, args->daddr, 4);
        } else if (args->family == 10) {
            copy_addr(ev.saddr, args->saddr_v6, 16);
            copy_addr(ev.daddr, args->daddr_v6, 16);
        }
        events.perf_submit(args, &ev, sizeof(ev));
        return 0;
    }
    '''

    b = BPF(text=program)

    def print_event(cpu, data, size):
        event = b['events'].event(data)
        old = TCP_STATE_NAMES.get(event.oldstate, str(event.oldstate))
        new = TCP_STATE_NAMES.get(event.newstate, str(event.newstate))
        if event.family == socket.AF_INET:
            src = socket.inet_ntoa(bytes(event.saddr[:4]))
            dst = socket.inet_ntoa(bytes(event.daddr[:4]))
        elif event.family == socket.AF_INET6:
            src = socket.inet_ntop(socket.AF_INET6, bytes(event.saddr))
            dst = socket.inet_ntop(socket.AF_INET6, bytes(event.daddr))
        else:
            return
        dport = socket.ntohs(event.dport)
        print(f"TCP {old} -> {new:<12} pid={event.pid:<6} {src}:{event.sport} -> {dst}:{dport}")

    print('Monitoring TCP socket state changes (Ctrl-C to stop)...')
    b['events'].open_perf_buffer(print_event)
    while True:
        try:
            b.perf_buffer_poll()
        except KeyboardInterrupt:
            break
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        prog='ss',
        description='utility to investigate sockets',
    )
    parser.add_argument('-t', '--tcp', action='store_true', help='display only TCP sockets')
    parser.add_argument('-u', '--udp', action='store_true', help='display only UDP sockets')
    parser.add_argument('-l', '--listening', action='store_true', help='display only listening sockets')
    parser.add_argument('-a', '--all', action='store_true', help='display all sockets')
    parser.add_argument('-n', '--numeric', action='store_true', help='do not resolve service names')
    parser.add_argument('-p', '--processes', action='store_true', help='show process using socket')
    parser.add_argument('-m', '--monitor', action='store_true', help='monitor socket events with eBPF')
    parser.add_argument('-4', '--ipv4', dest='ipv4', action='store_true', help='display only IPv4 sockets')
    parser.add_argument('-6', '--ipv6', dest='ipv6', action='store_true', help='display only IPv6 sockets')
    parser.add_argument('state', nargs='?', help='filter by state')
    args = parser.parse_args()

    if args.monitor:
        return monitor_with_bcc(args.tcp or True, args.udp or True)

    if not args.tcp and not args.udp:
        args.tcp = True
        args.udp = True

    if not args.ipv4 and not args.ipv6:
        args.ipv4 = True
        args.ipv6 = True

    sockets = collect_sockets(args.tcp, args.udp, args.ipv4, args.ipv6)
    states = [args.state.upper()] if args.state else []
    sockets = filter_sockets(sockets, args.listening, args.all, states)
    print_sockets(sockets, args.numeric, args.processes)
    return 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(0)
