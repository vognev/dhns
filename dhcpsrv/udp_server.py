import socket, traceback
from multiplexer.server import Server as BaseServer
from dhcplib.packet import Packet
from dhcpsrv import Handler


IP_PKTINFO = 8


class UdpServer(BaseServer):
    def __init__(self, addr, handler: Handler):
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        self._sock.setsockopt(socket.SOL_IP, IP_PKTINFO, 1)
        self._sock.bind(addr)
        self._handler = handler
        self._queue = []

    def read(self):
        buf, ancdata, _, addr = self._sock.recvmsg(512, socket.CMSG_SPACE(100))
        interface = self._get_cmsg_to(ancdata)

        if (addr[0] == '0.0.0.0'):
            addr = ('10.0.4.255', addr[1])

        try:
            query = Packet.parse(buf)
            answer = self._handler.handle(interface, query)
            self._queue.append((addr, answer))
        except Exception as e:
            traceback.print_exc()

    def write(self):
        if len(self._queue):
            tup = self._queue.pop(0)
            self._sock.sendto(tup[1].pack(), tup[0])

    def wqlen(self):
        return len(self._queue)

    def fileno(self):
        return self._sock.fileno()

    def _get_cmsg_to(self, ancdata):
        for level, type, data in ancdata:
            if level == socket.SOL_IP and type == IP_PKTINFO:
                return socket.inet_ntoa(data[4:8])
        return None
