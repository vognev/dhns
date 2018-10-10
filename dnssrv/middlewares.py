from dnslib import RR, DNSRecord, RDMAP, QTYPE, DNSLabel
from cachetools import LRUCache

from collections import defaultdict
from collections import namedtuple

import time, traceback, threading, json, re


Container = namedtuple('Container', 'id, name, running, addrs')
RE_VALIDNAME = re.compile('[^\w\d.-]')

def get(d, *keys):
    from functools import reduce
    empty = {}
    return reduce(lambda d, k: d.get(k, empty), keys, d) or None


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
                local_a = DNSRecord.parse(query.send(self.address, port=self.port, timeout=1.0))
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


class FixHandler(Middleware):
    def __init__(self, records):
        self.records = records

    def handle_dns_packet(self, query: DNSRecord, answer: DNSRecord):
        import random

        qname = query.q.qname
        qtype = query.q.qtype
        found = False

        records = []

        for rec in self.records:
            if qname == rec[0]:
                found = True
                if qtype == QTYPE.ANY:
                    records.append(rec)
                elif qtype == rec[1]:
                    records.append(rec)

        random.shuffle(records)

        for rec in records:
            answer.add_answer(RR(rname=rec[0], rtype=rec[1], ttl=60, rdata=RDMAP.get(QTYPE.get(rec[1]))(rec[2])))

        return found


class DockerHandler(Middleware):
    def __init__(self, docker='unix:///var/run/docker.sock', domain='docker'):
        from docker.client import DockerClient

        self._docker = DockerClient(docker, version='auto')
        self._domain = domain

        self._storage = defaultdict(set)
        self._lock = threading.Lock()

        threading.Thread(group=None, target=self.listen).start()

    def add(self, name, addr):
        key = self._key(name)
        if key:
            with self._lock:
                # log('table.add %s -> %s', name, addr)
                self._storage[key].add(addr)

    def get(self, name):
        key = self._key(name)
        if key:
            with self._lock:
                res = self._storage.get(key)
                if not res:
                    pass #log('table.get %s with NoneType' % (name))
                else:
                    pass #log('table.get %s with %s' % (name, ", ".join(addr for addr in res)))
                return res

    def rename(self, old_name, new_name):
        if not old_name or not new_name:
            return
        old_name = old_name.lstrip('/')
        old_key = self._key(old_name)
        new_key = self._key(new_name)
        with self._lock:
            self._storage[new_key] = self._storage.pop(old_key)
            #log('table.rename (%s -> %s)', old_name, new_name)

    def remove(self, name):
        key = self._key(name)
        if key:
            with self._lock:
                if key in self._storage:
                    # log('table.remove %s', name)
                    del self._storage[key]

    def _key(self, name):
        try:
            return DNSLabel(name.lower()).label
        except Exception:
            return None

    def __del__(self):
        self.running = False

    def listen(self):
        self.running = True

        events = self._docker.events()

        for container in self._docker.containers.list():
            for rec in self._inspect(container):
                for addr in rec.addrs:
                    self.add(rec.name, addr)

        for raw in events:
            if not self.running:
                break

            evt = json.loads(raw)
            if evt.get('Type', 'container') == 'container':
                cid = evt.get('id')
                if cid is None:
                    continue

                status = evt.get('status')
                if status in set(('start', 'die', 'rename')):
                    try:
                        container = self._docker.containers.get(cid)

                        for rec in self._inspect(container):
                            if status == 'start':
                                for addr in rec.addrs:
                                    self.add(rec.name, addr)

                            elif status == 'rename':
                                old_name = get(evt, 'Actor', 'Attributes', 'oldName')
                                new_name = get(evt, 'Actor', 'Attributes', 'name')
                                old_name = '.'.join((old_name, self._domain))
                                new_name = '.'.join((new_name, self._domain))
                                self.rename(old_name, new_name)

                            else:
                                self.remove(rec.name)

                    except Exception as e:
                        pass #log('Error: %s', e)

    def _inspect(self, container):
        name = get(container.attrs, 'Name')
        if not container.name:
            return None

        id = get(container.attrs, 'Id')
        labels = get(container.attrs, 'Config', 'Labels')
        state = get(container.attrs, 'State', 'Running')

        networks = get(container.attrs, 'NetworkSettings', 'Networks')
        ip_addrs = self._get_addrs(networks)

        return [ Container(id, name, state, ip_addrs) for name in self._get_names(name, labels) ]

    def _get_addrs(self, networks):
        return list(filter(None, [value['IPAddress'] for value in networks.values()]))

    def _get_names(self, name, labels):
        names = [ RE_VALIDNAME.sub('', name).rstrip('.') ]

        labels = labels or {}
        instance = int(labels.get('com.docker.compose.container-number', 1))
        service = labels.get('com.docker.compose.service')
        project = labels.get('com.docker.compose.project')

        if all((instance, service, project)):
            names.append('%d.%s.%s' % (instance, service, project))

            if instance == 1:
                names.append('%s.%s' % (service, project))

        names = [ '.'.join((name, self._domain)) for name in names ]

        domain = labels.get('com.dhns.domain')
        if domain is not None:
            for name in domain.split(';'):
                names.append(name)

        return names

    def handle_dns_packet(self, query: DNSRecord, answer: DNSRecord):
        addrs = None

        if query.q.qtype in (QTYPE.A, QTYPE.ANY):
            addrs = self.get(query.q.qname.idna())

        if addrs is not None:
            for addr in self._resolve_addresses(addrs):
                answer.add_answer(
                    RR(rname=query.q.qname, rtype=QTYPE.A, ttl=60, rdata=RDMAP["A"](addr))
                )
            return self

    def _resolve_addresses(self, addresses):
        list = []

        for addr in addresses:
            list.append(addr)

        return set(list)

