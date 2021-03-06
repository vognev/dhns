from select import select


class Multiplexer:
    def __init__(self, *args):
        self.servers = list(args)
        self.running = False

    def add(self, server):
        self.servers.append(server)

    def start(self):
            self.running = True
            while self.running:
                r, w, e = select(self.servers, [s for s in self.servers if s.wqlen()], [], .025)
                for srv in r:
                    srv.read()
                for srv in w:
                    srv.write()

    def stop(self):
        self.running = False


class Server:
    def read(self):
        raise NotImplemented

    def write(self):
        raise NotImplemented

    def wqlen(self):
        raise NotImplemented

    def fileino(self):
        raise NotImplemented

