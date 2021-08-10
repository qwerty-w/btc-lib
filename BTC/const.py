

MAX_ORDER = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141
P = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f

DEFAULT_VERSION = b'\x02\x00\x00\x00'
DEFAULT_LOCKTIME = b'\x00\x00\x00\x00'
DEFAULT_WITNESS_VERSION = 0
DEFAULT_SEQUENCE = b'\xff\xff\xff\xff'
DEFAULT_NETWORK = 'mainnet'

EMPTY_SEQUENCE = b'\x00\x00\x00\x00'

PREFIXES = {
    'wif': {
        'mainnet': b'\x80',
        'testnet': b'\xef'
    },
    'P2PKH': {
        'mainnet': b'\x00',
        'testnet': b'\x6f'
    },
    'P2SH': {
        'mainnet': b'\x05',
        'testnet': b'\xc4'
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
