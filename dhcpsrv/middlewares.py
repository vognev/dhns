import dhcplib
import struct
from dhcplib.packet import Packet
from socket import inet_ntoa, inet_aton
from dnssrv import Middleware as DnsMiddleware
from dnslib import RR, DNSRecord, RDMAP, QTYPE


class Middleware:
    def handle_dhcp_packet(self, interface, query: Packet, answer: Packet):
        raise NotImplemented


class MemoryPool(Middleware, DnsMiddleware):
    def __init__(self, address=None, netmask=None, nameservers=None, gateway=None, domain=None):
        self.domain = domain
        self.address = inet_aton(address)
        self.netmask = inet_aton(netmask)

        self.broadcast = bytes([(a | ~b & 255) for (a, b) in zip(self.address, self.netmask)])

        if nameservers:
            self.resolvers = bytearray()
            for ns in nameservers:
                self.resolvers.extend(inet_aton(ns))
        else:
            self.resolvers = None

        if gateway:
            self.gateway = inet_aton(gateway)
        else:
            self.gateway = None

        self.leases = {}
        self.offers = {}

    def handle_dhcp_packet(self, interface, query: Packet, answer: Packet):
        if interface == inet_ntoa(self.address):
            msg_type, = struct.unpack('!B', query.opts.get(dhcplib.DHCPOPT_MSG_TYPE))
            if msg_type == dhcplib.DHCPDISCOVER:
                print('DISCOVER')
                self.handle_discover(query, answer)
            elif msg_type == dhcplib.DHCPREQUEST:
                print('REQUEST')
                self.handle_request(query, answer)
            elif msg_type == dhcplib.DHCPDECLINE:
                print('DECLINE')
                self.handle_decline(query, answer)
            else:
                raise Exception('unsupported request type: ' + msg_type)
            return True

    def handle_dns_packet(self, query: DNSRecord, answer: DNSRecord):
        if self.domain and query.q.qname.matchSuffix(self.domain):
            if query.q.qtype in (QTYPE.A, QTYPE.ANY):
                dnsname = query.q.qname.stripSuffix(self.domain)
                ipaddr  = self.get_hostname_ip(dnsname.label[-1])
                if ipaddr:
                    answer.add_answer(
                        RR(rname=query.q.qname, rtype=QTYPE.A, ttl=3600, rdata=RDMAP["A"](inet_ntoa(ipaddr)))
                    )

    def handle_discover(self, query: Packet, answer: Packet):
        b_hwaddr = query.chaddr
        s_hwaddr = self.fmt_hwaddr(b_hwaddr, query.hlen)
        b_ipaddr = query.opts.get(dhcplib.DHCPOPT_IPADDR)

        hostname = query.opts.get(dhcplib.DHCPOPT_HOSTNAME, s_hwaddr)

        lease, offer = self.leases.pop(s_hwaddr, None), self.offers.pop(s_hwaddr, None)

        if b_ipaddr is None:
            if lease:
                b_ipaddr = lease[0]
            elif offer:
                b_ipaddr = offer[0]
            else:
                b_ipaddr = self.allocate()
        elif self.get_ip_hwaddr(self.offers, b_ipaddr):
            b_ipaddr = self.allocate()
        elif self.get_ip_hwaddr(self.leases, b_ipaddr):
            b_ipaddr = self.allocate()

        options = {
            dhcplib.DHCPOPT_IPADDR: b_ipaddr,
            dhcplib.DHCPOPT_BROADCAST: self.broadcast,
            dhcplib.DHCPOPT_LEASE_TIME: struct.pack('!I', 3600),
            # todo: ensure unique
            dhcplib.DHCPOPT_HOSTNAME: hostname
        }

        if self.gateway:
            options[dhcplib.DHCPOPT_GATEWAY] = self.gateway

        if self.resolvers:
            options[dhcplib.DHCPOPT_RESOLVER] = self.resolvers

        answer.opts[dhcplib.DHCPOPT_MSG_TYPE] = struct.pack('!B', dhcplib.DHCPOFFER)
        answer.yiaddr = b_ipaddr
        for (k, v) in options.items():
            answer.opts[k] = v

        self.offers[s_hwaddr] = (b_ipaddr, options)
        print(self.offers[s_hwaddr])

    def handle_request(self, query: Packet, answer: Packet):
        b_hwaddr = query.chaddr
        s_hwaddr = self.fmt_hwaddr(b_hwaddr, query.hlen)

        offer = self.offers.pop(s_hwaddr, None)
        if offer:
            b_ipaddr, options = offer
            answer.opts[dhcplib.DHCPOPT_MSG_TYPE] = struct.pack('!B', dhcplib.DHCPACK)
            answer.yiaddr = b_ipaddr

            for (k, v) in options.items():
                answer.opts[k] = v

            self.leases[s_hwaddr] = (b_ipaddr, options)
        else:
            answer.opts[dhcplib.DHCPOPT_MSG_TYPE] = struct.pack('!B', dhcplib.DHCPNAK)

    def handle_decline(self, query: Packet, answer: Packet):
        b_hwaddr = query.chaddr
        s_hwaddr = self.fmt_hwaddr(b_hwaddr, query.hlen)

        self.leases.pop(s_hwaddr, None)
        self.offers.pop(s_hwaddr, None)

        answer.opts[dhcplib.DHCPOPT_MSG_TYPE] = struct.pack('!B', dhcplib.DHCPACK)

    def allocate(self):
        address = struct.unpack('!I', self.address)[0]
        netsize = ~struct.unpack('!I', self.netmask)[0] & 0xffffffff - 2

        allocated = None
        for candidate in range(address + 1, address + netsize - 1):
            candidate = struct.pack('!I', candidate)
            if self.get_ip_hwaddr(self.offers, candidate):
                continue
            if self.get_ip_hwaddr(self.leases, candidate):
                continue
            allocated = candidate
            break

        if allocated is None:
            raise Exception('pool full')

        return allocated

    def get_hostname_ip(self, hostname):
        for idx in self.leases:
            if self.leases[idx][1].get(dhcplib.DHCPOPT_HOSTNAME, None) == hostname:
                return self.leases[idx][0]
        return None

    @classmethod
    def get_ip_hwaddr(cls, dictionary, aton):
        for idx in dictionary:
            if dictionary[idx][0] == aton:
                return idx
        return False

    @classmethod
    def fmt_hwaddr(cls, b_hwaddr, hwaddr_len):
        return ':'.join(['{:02x}'.format(b) for b in b_hwaddr[:hwaddr_len]])

