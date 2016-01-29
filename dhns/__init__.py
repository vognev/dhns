import dhcpsrv, dnssrv
from dnssrv.udp_server import UdpServer as DnsUdpServer
from dnssrv.middlewares import SysHandler
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
             DnsUdpServer(('0.0.0.0', int(getenv("DNSPORT",  5353))), self.dns),
            DhcpUdpServer(('0.0.0.0', int(getenv("DHCPPORT", 6767))), self.dhcp)
        )
        self.dns.add_middleware(SysHandler(), dnssrv.PRIO_LOWEST)

    def start(self):
        self.mul.start()

    def stop(self):
        self.mul.stop()

    def push(self, handler):
        if isinstance(handler, dnssrv.middlewares.Middleware):
            self.dns.add_middleware(handler)
        if isinstance(handler, dhcpsrv.middlewares.Middleware):
            self.dhcp.add_middleware(handler)