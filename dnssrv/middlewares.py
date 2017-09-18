from dnslib import RR, DNSRecord, RDMAP, QTYPE
from cachetools import LRUCache
from socket import inet_ntoa
import docker.client
import time, traceback, threading

class Middleware:
    def handle_dns_packet(self, query: DNSRecord, answer: DNSRecord):
        raise NotImplemented


class SrvHandler(Middleware):
    def __init__(self, glob='*', address=None, port=53):
        self.glob = glob
        self.address = address
        self.port = port

    def handle_dns_packet(self, query: DNSRecord, answer: DNSRecord):
        if query.q.qname.matchGlob(self.glob):
            try:
                local_a = DNSRecord.parse(query.send(self.address, port=self.port))
                for rr in local_a.rr:
                    answer.add_answer(rr)
                return True
            except:
                pass
            finally:
                return True


class GoogleDnsHandler(Middleware):
    def __init__(self):
        self.resolvers = [
            ("8.8.8.8", 53),
            ("8.8.4.4", 53)
        ]
        self.cache = LRUCache(64000)

    def handle_dns_packet(self, query: DNSRecord, answer: DNSRecord):
        key = "%s/%d/%d" % (query.q.qname, query.q.qclass, query.q.qtype)

        if key in self.cache:
            received, cached = self.cache[key]
            if not self.is_expired(received, cached):
                return self.from_cache(key, answer)

        for resolver in self.resolvers:
            try:
                res = DNSRecord.parse(query.send(resolver[0], resolver[1], timeout=5))
                if 0 == len(res.rr) or res.header.rcode:
                    return self.from_res(res, answer)
                else:
                    self.cache[key] = (time.time(), res)
                    return self.from_cache(key, answer)
            except:
                traceback.print_exc()

    def is_expired(self, cached, answer):
        now = time.time()
        for rr in answer.rr:
            if cached + rr.ttl < now:
                return True
        return False

    def from_cache(self, key, answer):
        now = time.time(); cached, res = self.cache[key]
        for rr in res.rr:
            rr.ttl -= int(now - cached)
            answer.add_answer(rr)
        answer.header.rcode = res.header.rcode
        return True

    def from_res(self, res, answer):
        for rr in res.rr:
            answer.add_answer(rr)
        answer.header.rcode = res.header.rcode
        return True


# todo: use .zone
class FixHandler(Middleware):
    def __init__(self, records):
        self.records = records

    def handle_dns_packet(self, query: DNSRecord, answer: DNSRecord):
        qname = query.q.qname
        qtype = query.q.qtype
        found = False

        for rec in self.records:
            if qname == rec[0]:
                found = True
                if qtype == QTYPE.ANY:
                    answer.add_answer(RR(rname=rec[0], rtype=rec[1], ttl=60, rdata=RDMAP.get(QTYPE.get(rec[1]))(rec[2])))
                elif qtype == rec[1]:
                    answer.add_answer(RR(rname=rec[0], rtype=rec[1], ttl=60, rdata=RDMAP.get(QTYPE.get(rec[1]))(rec[2])))
                    break
        return found


class DockerHandler(Middleware):
    def __init__(self, baseurl=None):
        self.client     = docker.client.Client(baseurl)
        self.lock       = threading.Lock()
        self.registry   = {}
        self.running    = True
        threading.Thread(group=None, target=self.worker).start()

    def __del__(self):
        self.running = False

    def worker(self):
        registry = {}
        while self.running:
            for item in self.client.containers(all=True, quiet=True):
                res = self.client.inspect_container(item['Id'])
                hostname = res.get('Config', {}).get('Hostname', None)
                domain   = res.get('Config', {}).get('Domainname', None)

                if not hostname or (domain and not hostname):
                    continue

                addrs    = []

                settings = res.get('NetworkSettings', {})
                if settings.get('IPAddress'):
                    addrs.append(settings.get('IPAddress'))
                else:
                    for (name, net) in settings.get('Networks', {}).items():
                        if net.get('IPAddress'):
                            addrs.append(net['IPAddress'])

                if domain:
                    registry[".".join((hostname, domain))] = addrs
                else:
                    registry[hostname] = addrs

            with self.lock:
                self.registry = registry

            time.sleep(30)

    def handle_dns_packet(self, query: DNSRecord, answer: DNSRecord):
        with self.lock:
            name = b'.'.join(query.q.qname.label).decode('utf8')
            addr = self.registry.get(name)

        if addr is not None:
            if query.q.qtype in (QTYPE.A, QTYPE.ANY):
                for ip in self.registry.get(name):
                    answer.add_answer(
                        RR(rname=query.q.qname, rtype=QTYPE.A, ttl=60, rdata=RDMAP["A"](ip))
                    )
            return self

