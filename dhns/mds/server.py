from dhns.mux import Server as MuxServer
from dhns.mds.handler import Handler
import socket, threading, traceback

class TcpServer(MuxServer):
    def __init__(self, addr, public_keys = list()):
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.setblocking(0)
        self._sock.bind(addr)
        self._sock.listen()

        self._opts = {
            'public_keys': public_keys
        }

    def read(self):
        conn, addr = self._sock.accept()

        try:
            self.process(conn, addr)
        except ValueError:
            conn.close()
        except:
            traceback.print_exc()
            conn.close()

        #thread = threading.Thread(group=None, target=self.process, args=(conn, addr))
        #thread.start()

    def write(self):
        pass

    def wqlen(self):
        return 0

    def fileno(self):
        return self._sock.fileno()

    def process(self, conn, addr):
        handler = Handler(conn, addr, self._opts)
        handler.handle_one_request()