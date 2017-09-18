import dhcpsrv, dnssrv
from dnssrv.udp_server import UdpServer as DnsUdpServer
from dnssrv.middlewares import GoogleDnsHandler
from dhcpsrv.udp_server import UdpServer as DhcpUdpServer
from multiplexer import Multiplexer
import dhcpsrv.middlewares
import dnssrv.middlewares
from os import getenv


class DhcpNameserver():
    def __init__(self):
        self.dns  = dnssrv.Handler()
        self.dhcp = dhcpsrv.Handler()
        self.mul  = Multiplexer(
             DnsUdpServer(('', int(getenv("DNSPORT",  5353))), self.dns),
            DhcpUdpServer(('', int(getenv("DHCPPORT", 6767))), self.dhcp)
        )

    def start(self):
        self.mul.start()

    def stop(self):
        self.mul.stop()

    def push(self, handler):
        if isinstance(handler, dnssrv.middlewares.Middleware):
            self.dns.add_middleware(handler, dnssrv.PRIO_NORMAL)
        if isinstance(handler, dhcpsrv.middlewares.Middleware):
            self.dhcp.add_middleware(handler, dnssrv.PRIO_NORMAL)

    def fallback(self, handler):
        if isinstance(handler, dnssrv.middlewares.Middleware):
            self.dns.add_middleware(handler, dnssrv.PRIO_LOWEST)
        if isinstance(handler, dhcpsrv.middlewares.Middleware):
            self.dhcp.add_middleware(handler, dnssrv.PRIO_LOWEST)