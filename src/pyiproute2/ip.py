#!/usr/bin/env python3
"""ip - show / manipulate routing, network devices, interfaces and tunnels"""

import argparse
import fcntl
import os
import socket
import struct
import sys

SIOCGIFADDR = 0x8915
SIOCGIFNETMASK = 0x891b
SIOCGIFHWADDR = 0x8927
SIOCGIFMTU = 0x8921
SIOCGIFFLAGS = 0x8913
IF_NAMESIZE = 16

IFF_UP = 0x1


def read_file(path: str) -> str:
    try:
        with open(path) as handle:
            return handle.read().strip()
    except OSError:
        return ''


def qdisc_for_interface(iface: str) -> str:
    # Try sysfs first; fall back to a netlink query if unavailable.
    qdisc = read_file(f'/sys/class/net/{iface}/qdisc')
    if qdisc:
        return qdisc
    try:
        import socket as nl_socket
        import struct
        RTM_GETQDISC = 0x26
        RTM_NEWQDISC = 0x24
        NLMSG_DONE = 0x3
        NLM_F_REQUEST = 0x1
        NLM_F_DUMP = 0x300
        TCA_KIND = 1
        ifindex = int(read_file(f'/sys/class/net/{iface}/ifindex') or 0)
        if not ifindex:
            return 'noqueue'
        sock = nl_socket.socket(nl_socket.AF_NETLINK, nl_socket.SOCK_DGRAM, 0)
        try:
            seq = 1
            tcmsg = struct.pack('BBHI III', 0, 0, 0, ifindex, 0, 0, 0)
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
                        if tcm_ifindex == ifindex:
                            attr_offset = tcmsg_start + 20
                            while attr_offset + 4 <= len(buf):
                                rta_len, rta_type = struct.unpack_from('HH', buf, attr_offset)
                                if rta_len < 4:
                                    break
                                if rta_type == TCA_KIND:
                                    kind = buf[attr_offset + 4:attr_offset + rta_len].split(b'\x00', 1)[0]
                                    return kind.decode('utf-8', 'replace')
                                attr_offset += (rta_len + 3) & ~3
                offset += nlmsg_len
                offset = (offset + 3) & ~3
        finally:
            sock.close()
    except Exception:
        pass
    return 'noqueue'


def link_show(args) -> int:
    try:
        interfaces = sorted(os.listdir('/sys/class/net'))
    except OSError as exc:
        print(f'ip: {exc}', file=sys.stderr)
        return 1

    for iface in interfaces:
        if args.dev and iface != args.dev:
            continue

        operstate = read_file(f'/sys/class/net/{iface}/operstate')
        mtu = read_file(f'/sys/class/net/{iface}/mtu')
        address = read_file(f'/sys/class/net/{iface}/address')
        if not address:
            address = '00:00:00:00:00:00'

        flag_list = ['UP'] if operstate == 'up' or operstate == 'unknown' else ['DOWN']
        if os.path.exists(f'/sys/class/net/{iface}/bridge'):
            flag_list.append('MASTER')
        if os.path.exists(f'/sys/class/net/{iface}/master'):
            flag_list.append('SLAVE')

        qdisc = qdisc_for_interface(iface)
        print(f'{iface}: <{",".join(flag_list)}> mtu {mtu} qdisc {qdisc} state {operstate}')
        print(f'    link/{address}')
    return 0


def get_ipv4_address(iface: str) -> tuple[str, str] | None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        ifreq = struct.pack('16sH14s', iface.encode(), socket.AF_INET, b'\x00' * 14)
        addr = fcntl.ioctl(sock, SIOCGIFADDR, ifreq)
        ip = socket.inet_ntoa(addr[20:24])

        maskreq = struct.pack('16sH14s', iface.encode(), socket.AF_INET, b'\x00' * 14)
        mask = fcntl.ioctl(sock, SIOCGIFNETMASK, maskreq)
        netmask = socket.inet_ntoa(mask[20:24])
        return ip, netmask
    except OSError:
        return None
    finally:
        sock.close()


def read_ipv6_addresses(iface: str) -> list:
    addrs = []
    try:
        with open('/proc/net/if_inet6') as handle:
            for line in handle:
                fields = line.split()
                if len(fields) >= 6 and fields[5] == iface:
                    raw = fields[0]
                    addr = ':'.join(raw[i:i + 4] for i in range(0, 32, 4))
                    # compress
                    addr = socket.inet_ntop(socket.AF_INET6, socket.inet_pton(socket.AF_INET6, addr))
                    prefix = int(fields[2], 16)
                    scope = int(fields[3], 16)
                    addrs.append((addr, prefix, scope))
    except OSError:
        pass
    return addrs


def addr_show(args) -> int:
    try:
        interfaces = sorted(os.listdir('/sys/class/net'))
    except OSError as exc:
        print(f'ip: {exc}', file=sys.stderr)
        return 1

    for iface in interfaces:
        if args.dev and iface != args.dev:
            continue

        operstate = read_file(f'/sys/class/net/{iface}/operstate')
        print(f'{iface}: <{operstate.upper()}>')

        ipv4 = get_ipv4_address(iface)
        if ipv4:
            ip, netmask = ipv4
            prefix = sum(bin(int(x)).count('1') for x in netmask.split('.'))
            print(f'    inet {ip}/{prefix} scope global {iface}')

        for addr, prefix, scope in read_ipv6_addresses(iface):
            scope_name = {0: 'global', 16: 'host', 32: 'link', 64: 'site'}.get(scope, str(scope))
            print(f'    inet6 {addr}/{prefix} scope {scope_name}')
    return 0


def route_show(args) -> int:
    try:
        with open('/proc/net/route') as handle:
            next(handle)
            for line in handle:
                fields = line.split()
                if len(fields) < 8:
                    continue
                iface = fields[0]
                dest = socket.inet_ntoa(struct.pack('<I', int(fields[1], 16)))
                gateway = socket.inet_ntoa(struct.pack('<I', int(fields[2], 16)))
                mask = socket.inet_ntoa(struct.pack('<I', int(fields[7], 16)))
                prefix = sum(bin(int(x)).count('1') for x in mask.split('.'))
                flags = fields[3]
                metric = fields[6]
                if dest == '0.0.0.0':
                    dest_text = 'default'
                else:
                    dest_text = f'{dest}/{prefix}'
                gw_text = f' via {gateway}' if gateway != '0.0.0.0' else ''
                print(f'{dest_text} dev {iface}{gw_text} metric {metric}')
    except OSError as exc:
        print(f'ip: {exc}', file=sys.stderr)
        return 1

    try:
        with open('/proc/net/ipv6_route') as handle:
            for line in handle:
                fields = line.split()
                if len(fields) < 10:
                    continue
                dest = ':'.join(fields[0][i:i + 4] for i in range(0, 32, 4))
                dest = socket.inet_ntop(socket.AF_INET6, socket.inet_pton(socket.AF_INET6, dest))
                prefix = int(fields[1], 16)
                src = ':'.join(fields[2][i:i + 4] for i in range(0, 32, 4))
                src = socket.inet_ntop(socket.AF_INET6, socket.inet_pton(socket.AF_INET6, src))
                src_prefix = int(fields[3], 16)
                gateway = ':'.join(fields[4][i:i + 4] for i in range(0, 32, 4))
                gateway = socket.inet_ntop(socket.AF_INET6, socket.inet_pton(socket.AF_INET6, gateway))
                metric = int(fields[5], 16)
                ref = fields[6]
                use = fields[7]
                flags = fields[8]
                iface = fields[9]
                if dest == '::':
                    dest_text = 'default'
                else:
                    dest_text = f'{dest}/{prefix}'
                gw_text = f' via {gateway}' if gateway != '::' else ''
                print(f'{dest_text} dev {iface}{gw_text} metric {metric}')
    except OSError:
        pass
    return 0


def neigh_show(args) -> int:
    try:
        with open('/proc/net/arp') as handle:
            next(handle)
            for line in handle:
                fields = line.split()
                if len(fields) < 6:
                    continue
                ip = fields[0]
                hw_type = fields[1]
                flags = fields[2]
                mac = fields[3]
                mask = fields[4]
                iface = fields[5]
                state = 'REACHABLE' if '0x2' in flags else 'STALE'
                print(f'{ip} dev {iface} lladdr {mac} {state}')
    except OSError as exc:
        print(f'ip: {exc}', file=sys.stderr)
        return 1

    try:
        neigh_dir = '/proc/net/neigh'
        for entry in os.listdir(neigh_dir):
            path = f'{neigh_dir}/{entry}'
            try:
                with open(path) as handle:
                    for line in handle:
                        fields = line.split()
                        if len(fields) < 4:
                            continue
                        ip = fields[0]
                        lladdr = fields[4] if len(fields) > 4 else ''
                        state_num = int(fields[2]) if fields[2].isdigit() else 0
                        states = {1: 'INCOMPLETE', 2: 'REACHABLE', 4: 'STALE', 8: 'DELAY',
                                  16: 'PROBE', 32: 'FAILED', 64: 'NOARP', 128: 'PERMANENT'}
                        state = states.get(state_num, str(state_num))
                        if lladdr and ':' in ip:
                            print(f'{ip} dev {entry} lladdr {lladdr} {state}')
            except OSError:
                continue
    except OSError:
        pass
    return 0


def monitor_with_bcc() -> int:
    try:
        from bcc import BPF
    except ImportError:
        print('ip: BCC is required for monitor mode', file=sys.stderr)
        return 1

    program = '''
    #include <uapi/linux/ptrace.h>

    struct event {
        u32 len;
        char name[16];
    };

    BPF_PERF_OUTPUT(events);

    TRACEPOINT_PROBE(net, net_dev_queue) {
        struct event ev = {};
        ev.len = args->len;
        u32 name_off = 0;
        bpf_probe_read(&name_off, sizeof(name_off), (char *)args + 20);
        char *name = (char *)args + (name_off & 0xFFFF);
        bpf_probe_read_str(&ev.name, sizeof(ev.name), name);
        events.perf_submit(args, &ev, sizeof(ev));
        return 0;
    }
    '''

    b = BPF(text=program)

    def print_event(cpu, data, size):
        event = b['events'].event(data)
        name = event.name.decode('utf-8', 'replace').strip('\x00')
        print(f'[NET] dev={name} len={event.len}')

    print('Monitoring network device queue events (Ctrl-C to stop)...')
    b['events'].open_perf_buffer(print_event)
    while True:
        try:
            b.perf_buffer_poll()
        except KeyboardInterrupt:
            break
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        prog='ip',
        description='show / manipulate routing, network devices, interfaces and tunnels',
    )
    subparsers = parser.add_subparsers(dest='object')

    link = subparsers.add_parser('link', help='network device')
    link.add_argument('action', nargs='?', default='show', choices=['show'])
    link.add_argument('dev', nargs='?')

    addr = subparsers.add_parser('addr', help='protocol address')
    addr.add_argument('action', nargs='?', default='show', choices=['show'])
    addr.add_argument('dev', nargs='?')

    route = subparsers.add_parser('route', help='routing table entry')
    route.add_argument('action', nargs='?', default='show', choices=['show'])

    neigh = subparsers.add_parser('neigh', help='neighbor/ARP tables')
    neigh.add_argument('action', nargs='?', default='show', choices=['show'])

    monitor = subparsers.add_parser('monitor', help='monitor network events with eBPF')

    args = parser.parse_args()

    if args.object == 'link':
        return link_show(args)
    if args.object == 'addr':
        return addr_show(args)
    if args.object == 'route':
        return route_show(args)
    if args.object == 'neigh':
        return neigh_show(args)
    if args.object == 'monitor':
        return monitor_with_bcc()

    parser.print_help()
    return 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(0)
