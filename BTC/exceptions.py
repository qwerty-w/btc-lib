

class InvalidWif(Exception):  # wif
    pass


class InvalidAddress(Exception):  # addr, type=None, network=None
    pass


class InvalidHash160(Exception):  # addr
    pass


class UnsupportedSegwitVersion(Exception):  # ver
    pass
