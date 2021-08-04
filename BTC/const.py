

MAX_ORDER = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141
P = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f

DEFAULT_VERSION = b'\x02\x00\x00\x00'
DEFAULT_LOCKTIME = b'\x00\x00\x00\x00'
DEFAULT_WITNESS_VERSION = 0
DEFAULT_SEQUENCE = b'\xff\xff\xff\xff'

PREFIXES = {
    'wif': {
        'mainnet': b'\x80',
        'testnet': b'\xef'
    },
    'bech32': {
        'mainnet': 'bc',
        'testnet': 'tb'
    }
}

SIGHASHES = {
    'all': 0x01,
    'none': 0x02,
    'single': 0x03,
    'anyonecanpay': 0x80
}
