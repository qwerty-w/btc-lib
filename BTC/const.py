

MAX_ORDER = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141
P = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f

DEFAULT_WITNESS_VERSION = 0

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
