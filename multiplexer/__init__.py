from multiplexer.server import Server
from select import select

class Multiplexer:
    def __init__(self, *args):
        self.servers = args
        self.running = False

    def start(self):
            self.running = True
            while self.running:
                r, w, e = select(self.servers, [s for s in self.servers if s.wqlen()], [], 10)
                for srv in r:
                    srv.read()
                for srv in w:
                    srv.write()

    def stop(self):
        self.running = False


