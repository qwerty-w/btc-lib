

MAX_ORDER = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141

PREFIXES = {
    'wif': {
        'mainnet': b'\x80',
        'testnet': b'\xef'
    }
}

SIGHASHES = {
    'all': 0x01,
    'none': 0x02,
    'single': 0x03,
    'anyonecanpay': 0x80
}
