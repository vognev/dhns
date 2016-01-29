import dhcplib, struct, io, socket
import dhcplib.errors as errors


DHCPMagic = bytes(bytearray((0x63, 0x82, 0x53, 0x63)))
UInt8 = '!B'
UInt16 = '!H'
UInt32 = '!I'


class Packet:

    def is_incoming(self):
        return 1 == self.op

    def is_broadcast(self):
        return self.flags & 0x8000

    def get_dhcp_type(self):
        try:
            return struct.unpack(UInt8, self.opts[53])[0]
        except AttributeError:
            return None
        except KeyError:
            return None

    def __init__(self):
        self.op = 0
        self.htype = 0
        self.hlen = 0
        self.hops = 0
        self.xid = 0
        self.secs = 0
        self.flags = 0
        self.ciaddr = bytearray(4)
        self.yiaddr = bytearray(4)
        self.siaddr = bytearray(4)
        self.giaddr = bytearray(4)
        self.chaddr = bytearray(16)
        self.sname = bytearray(64)
        self.file = bytearray(128)
        self.opts = {}

    def reply(self):
        reply = Packet()
        reply.op = dhcplib.BOOTREPLY
        reply.htype = self.htype
        reply.hlen = self.hlen
        reply.xid = self.xid
        reply.flags = self.flags

        reply.siaddr = self.siaddr
        reply.giaddr = self.giaddr
        reply.ciaddr = self.ciaddr
        reply.chaddr = self.chaddr

        reply.sname = bytearray(socket.gethostname(), 'ascii').ljust(64, bytes(chr(0), 'ascii'))

        return reply

    @classmethod
    def parse(cls, data: bytes):
        # todo: eof, get/set
        mypk = cls()
        myio = io.BytesIO(data)

        mypk.op,        = struct.unpack(UInt8, myio.read(struct.calcsize(UInt8)))
        mypk.htype,     = struct.unpack(UInt8, myio.read(struct.calcsize(UInt8)))
        mypk.hlen,      = struct.unpack(UInt8, myio.read(struct.calcsize(UInt8)))
        mypk.hops,      = struct.unpack(UInt8, myio.read(struct.calcsize(UInt8)))

        mypk.xid,       = struct.unpack(UInt32, myio.read(struct.calcsize(UInt32)))

        mypk.secs,      = struct.unpack(UInt16, myio.read(struct.calcsize(UInt16)))
        mypk.flags,     = struct.unpack(UInt16, myio.read(struct.calcsize(UInt16)))

        myio.readinto(mypk.ciaddr)
        myio.readinto(mypk.yiaddr)
        myio.readinto(mypk.siaddr)
        myio.readinto(mypk.giaddr)
        myio.readinto(mypk.chaddr)
        myio.readinto(mypk.sname)
        myio.readinto(mypk.file)

        magic = myio.read(4)
        if magic != DHCPMagic:
            raise errors.InvalidMagic

        while True:
            opt_code, = struct.unpack(UInt8, myio.read(struct.calcsize(UInt8)))
            if 0 == opt_code:
                continue
            if 255 == opt_code:
                break
            opt_len,  = struct.unpack(UInt8, myio.read(struct.calcsize(UInt8)))
            mypk.opts[opt_code] = myio.read(opt_len)

        return mypk

    def pack(self):

        myio = io.BytesIO()

        myio.write(struct.pack(UInt8,   self.op))
        myio.write(struct.pack(UInt8,   self.htype))
        myio.write(struct.pack(UInt8,   self.hlen))
        myio.write(struct.pack(UInt8,   self.hops))

        myio.write(struct.pack(UInt32,  self.xid))

        myio.write(struct.pack(UInt16,  self.secs))
        myio.write(struct.pack(UInt16,  self.flags))

        myio.write(self.ciaddr)
        myio.write(self.yiaddr)
        myio.write(self.siaddr)
        myio.write(self.giaddr)
        myio.write(self.chaddr)
        myio.write(self.sname)
        myio.write(self.file)

        myio.write(DHCPMagic)

        for code, val in self.opts.items():
            val_len = len(val)
            myio.write(struct.pack(UInt8, code))
            myio.write(struct.pack(UInt8, val_len))
            myio.write(val)

        myio.write(struct.pack(UInt8, 255))

        return myio.getvalue()
