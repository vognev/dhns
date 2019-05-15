import struct, logging, shelve
from socket import inet_ntoa, inet_aton
from dnslib import RR, DNSRecord, RDMAP, QTYPE
from dhns.dhcp.proto.packet import Packet
from dhns.dhcp import Middleware
from dhns.dns import Middleware as DnsMiddleware
import dhns.dhcp.proto as proto

# todo: merge lease/offer
# todo: inject lease time
# todo: handle expiration
class MemoryPool(Middleware, DnsMiddleware):
    def __init__(self, address=None, netmask=None, nameservers=None, gateway=None, domain=None, entries=None):
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

        self.leases = shelve.open('%s-leases' % domain)
        self.offers = shelve.open('%s-offers' % domain)

        self.entries = entries if entries else {}

        self.reserved = {}
        for (k, v) in self.entries.items():
            addr = v.get('address')
            if addr:
                self.reserved[inet_aton(addr)] = True

    def handle_dhcp_packet(self, interface, query: Packet, answer: Packet):
        if interface == inet_ntoa(self.address):
            answer.opts[proto.DHCPOPT_SERVER_ID] = self.address
            msg_type, = struct.unpack('!B', query.opts.get(proto.DHCPOPT_MSG_TYPE))
            if msg_type == proto.DHCPDISCOVER:
                self.handle_discover(query, answer)
            elif msg_type == proto.DHCPREQUEST:
                self.handle_request(query, answer)
            elif msg_type == proto.DHCPDECLINE:
                self.handle_decline(query, answer)
            elif msg_type == proto.DHCPRELEASE:
                self.handle_release(query, answer)
            else:
                logging.info('dhcp: unsupported request type: %s' % msg_type)
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
            return self

    def handle_discover(self, query: Packet, answer: Packet):
        b_hwaddr = query.chaddr
        s_hwaddr = self.fmt_hwaddr(b_hwaddr, query.hlen)
        b_ipaddr = query.opts.get(proto.DHCPOPT_IPADDR)

        logging.info('dhcp: discover - %s', s_hwaddr)

        lease, offer = self.leases.pop(s_hwaddr, None), self.offers.pop(s_hwaddr, None)

        if b_ipaddr is None:
            b_ipaddr = offer[0] if offer else self.allocate(s_hwaddr)
        elif self.get_ip_hwaddr(self.offers, b_ipaddr):
            b_ipaddr = self.allocate(s_hwaddr)
        elif self.get_ip_hwaddr(self.leases, b_ipaddr):
            b_ipaddr = self.allocate(s_hwaddr)
        elif not self.addr_in_network(b_ipaddr):
            b_ipaddr = self.allocate(s_hwaddr)

        options = self.get_options(s_hwaddr, query)
        self.offers[s_hwaddr] = (b_ipaddr, options)

        answer.opts[proto.DHCPOPT_MSG_TYPE] = struct.pack('!B', proto.DHCPOFFER)
        answer.yiaddr = b_ipaddr
        for (k, v) in options.items():
            answer.opts[k] = v

    def handle_request(self, query: Packet, answer: Packet):
        b_hwaddr = query.chaddr
        s_hwaddr = self.fmt_hwaddr(b_hwaddr, query.hlen)
        b_ipaddr = query.opts.get(proto.DHCPOPT_IPADDR)

        logging.info('dhcp: request - %s', s_hwaddr)

        lease, offer = self.leases.pop(s_hwaddr, None), self.offers.pop(s_hwaddr, None)

        if offer:
            b_ipaddr, options = offer
        else:
            if b_ipaddr is None:
                b_ipaddr = self.allocate(s_hwaddr)
            elif self.get_ip_hwaddr(self.offers, b_ipaddr):
                b_ipaddr = self.allocate(s_hwaddr)
            elif self.get_ip_hwaddr(self.leases, b_ipaddr):
                b_ipaddr = self.allocate(s_hwaddr)
            elif not self.addr_in_network(b_ipaddr):
                b_ipaddr = self.allocate(s_hwaddr)
            options = self.get_options(s_hwaddr, query)

        self.leases[s_hwaddr] = (b_ipaddr, options)

        answer.opts[proto.DHCPOPT_MSG_TYPE] = struct.pack('!B', proto.DHCPACK)
        answer.yiaddr = b_ipaddr
        for (k, v) in options.items():
            answer.opts[k] = v

    def handle_decline(self, query: Packet, answer: Packet):
        b_hwaddr = query.chaddr
        s_hwaddr = self.fmt_hwaddr(b_hwaddr, query.hlen)

        logging.info('dhcp: decline - %s', s_hwaddr)

        self.leases.pop(s_hwaddr, None)
        self.offers.pop(s_hwaddr, None)

        answer.opts[proto.DHCPOPT_MSG_TYPE] = struct.pack('!B', proto.DHCPACK)

    def handle_release(self, query: Packet, answer: Packet):
        b_hwaddr = query.chaddr
        s_hwaddr = self.fmt_hwaddr(b_hwaddr, query.hlen)

        logging.info('dhcp: release - %s', s_hwaddr)

        self.leases.pop(s_hwaddr, None)
        self.offers.pop(s_hwaddr, None)

        answer.opts[proto.DHCPOPT_MSG_TYPE] = struct.pack('!B', proto.DHCPACK)

    def allocate(self, s_hwaddr):
        hostopts = self.entries.get(s_hwaddr)
        if hostopts and hostopts.get("address"):
            return inet_aton(hostopts.get("address"))

        address = struct.unpack('!I', self.address)[0]
        netsize = ~struct.unpack('!I', self.netmask)[0] & 0xffffffff - 2

        allocated = None
        for candidate in range(address + 1, address + netsize - 1):
            candidate = struct.pack('!I', candidate)
            if self.get_ip_hwaddr(self.offers, candidate):
                continue
            if self.get_ip_hwaddr(self.leases, candidate):
                continue
            if self.reserved.get(candidate):
                continue
            allocated = candidate
            break

        if allocated is None:
            raise Exception('pool full')

        return allocated

    def get_hostname_ip(self, hostname):
        for idx in self.leases:
            if self.leases[idx][1].get(proto.DHCPOPT_HOSTNAME, None) == hostname:
                return self.leases[idx][0]
        return None

    def get_options(self, hwaddr, query):
        options = {
            proto.DHCPOPT_NETMASK: self.netmask,
            proto.DHCPOPT_BROADCAST: self.broadcast,
            proto.DHCPOPT_LEASE_TIME: struct.pack('!I', 3600),
            proto.DHCPOPT_DOMAIN: self.domain
        }

        if self.gateway:
            options[proto.DHCPOPT_GATEWAY] = self.gateway

        if self.resolvers:
            options[proto.DHCPOPT_RESOLVER] = self.resolvers

        if self.entries.get(hwaddr):
            for (idx, val) in self.entries[hwaddr].get("options", {}).items():
                options[idx] = val

        if self.entries.get(hwaddr, {}).get("hostname"):
            options[proto.DHCPOPT_HOSTNAME] = bytes(self.entries.get(hwaddr).get("hostname"), 'ascii')
        elif query.opts.get(proto.DHCPOPT_HOSTNAME):
            options[proto.DHCPOPT_HOSTNAME] = query.opts[proto.DHCPOPT_HOSTNAME]
        elif not options.get(proto.DHCPOPT_HOSTNAME):
            options[proto.DHCPOPT_HOSTNAME] = bytes(hwaddr, 'ascii')

        return options

    def addr_in_network(self, b_ipaddr):
        address = bytes([(a & b) for (a, b) in zip(b_ipaddr, self.netmask)])
        return address == self.address

    @classmethod
    def get_ip_hwaddr(cls, dictionary, aton):
        for idx in dictionary:
            if dictionary[idx][0] == aton:
                return idx
        return False

    @classmethod
    def fmt_hwaddr(cls, b_hwaddr, hwaddr_len):
        return (''.join(['{:02x}'.format(b) for b in b_hwaddr[:hwaddr_len]])).upper()

