from dnssrv.middlewares import SrvHandler, DockerHandler
from dhcpsrv.middlewares import MemoryPool
import dhns, logging, socket, struct
#todo: use dsl, TCP/UDP servers
logging.basicConfig(level = logging.INFO, format='%(asctime)s %(message)s')

server = dhns.DhcpNameserver()
server.push(MemoryPool(
    address='10.0.4.1',
    netmask='255.255.255.0',
    gateway='10.0.4.1',
    nameservers=['10.0.4.1'],
    domain=b'lxcnet',
    globals={
        'file': b'/pxelinux.0',
        'siaddr': socket.inet_aton('10.0.4.1')
    },
    entries={

    }
))

server.push(SrvHandler(
    suffix='lxcsrv.',
    address='192.168.1.3'
))

server.push(DockerHandler(
    baseurl='unix:///var/run/docker.sock'
))

try:
    server.start()
except KeyboardInterrupt:
    server.stop()


