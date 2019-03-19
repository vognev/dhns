from dhns.mux import Multiplexer
from os import getenv
import dhns.dns, dhns.dhcp, dhns.dns.server, dhns.dhcp.server


PRIO_HIGHEST = 100
PRIO_NORMAL = 50
PRIO_LOWEST = 0


class Server():
    def __init__(self):
        self.dns  = dhns.dns.Handler()
        self.dhcp = dhns.dhcp.Handler()
        self.mul  = Multiplexer(
             dhns.dns.server.UdpServer(('', int(getenv("DNSPORT",  5353))), self.dns),
            dhns.dhcp.server.UdpServer(('', int(getenv("DHCPPORT", 6767))), self.dhcp)
        )

    def start(self):
        self.mul.start()

    def stop(self):
        self.mul.stop()

    def use(self, handler):
        if isinstance(handler, dhns.dns.Middleware):
            self.dns.add_middleware(handler, PRIO_NORMAL)
        if isinstance(handler, dhns.dhcp.Middleware):
            self.dhcp.add_middleware(handler, PRIO_NORMAL)

    def fallback(self, handler):
        if isinstance(handler, dhns.dns.Middleware):
            self.dns.add_middleware(handler, PRIO_LOWEST)
        if isinstance(handler, dhns.dhcp.Middleware):
            self.dhcp.add_middleware(handler, PRIO_LOWEST)
