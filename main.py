from dhns.dhcp.memory_pool import MemoryPool
import dhns.dns.google, dhns.dns.docker, logging
logging.basicConfig(level = logging.INFO, format='%(asctime)s %(message)s')

server = dhns.Server()

server.use(dhns.dns.docker.Resolver(
    docker = 'unix:///var/run/docker.sock',
    domain = 'docker',
))

server.use(MemoryPool(
    address='10.3.2.1',
    netmask='255.255.255.0',
    gateway='10.3.2.1',
    nameservers=['10.3.2.1'],
    domain=b'kvm'
))

server.fallback(dhns.dns.google.Resolver())

try:
    server.start()
except KeyboardInterrupt:
    server.stop()


