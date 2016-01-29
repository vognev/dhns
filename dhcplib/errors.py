class InvalidMagic(Exception):
    pass


class NotIncomingPacket(Exception):
    def __init__(self, packet):
        self.packet = packet
        super()


class UnsupportedPacket(Exception):
    def __init__(self, packet):
        self.packet = packet
        super()