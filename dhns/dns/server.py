import socket, traceback, threading, logging
from dnslib import DNSRecord
from dhns.mux import Server as MuxServer
from dhns.dns import Handler


IP_PKTINFO = 8


class UdpServer(MuxServer):
    def __init__(self, addr, handler: Handler):
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.setsockopt(socket.SOL_IP, IP_PKTINFO, 1)
        self._sock.bind(addr)
        self._handler = handler
        self._queue = []

        _, self._port = addr

    def read(self):
        buf, ancdata, _, addr = self._sock.recvmsg(512, socket.CMSG_SPACE(100))
        respond = self._get_cmsg_to(ancdata).encode('utf8')

        thread = threading.Thread(group=None, target=self.process, args=(buf, addr, respond))
        thread.start()

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

    def process(self, buf, addr, respond):
        try:
            query = DNSRecord.parse(buf)
            logging.debug("DNS Q %s FROM: %s:%d" % (query.q.qname, addr[0], addr[1]))
            answer = self._handler.handle(query)

            # respond on requested interface
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind((respond, self._port))
            sock.sendto(answer.pack(), addr)
            sock.close()

        except Exception:
            traceback.print_exc()
