from enum import Enum


class AddressType(Enum):
    P2PKH = 'P2PKH'
    P2SH_P2WPKH = 'P2SH_P2WPKH'
    P2WPKH = 'P2WPKH'
    P2WSH = 'P2WSH'
    P2TR = 'P2TR'


class NetworkType(Enum):
    MAIN = 'mainnet'
    TEST = 'testnet'

    def toggle(self) -> 'NetworkType':
        return sorted([self.MAIN, self.TEST], key=lambda x: x == self)[0]


MAX_ORDER = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141
P = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f

DEFAULT_VERSION = 2
DEFAULT_LOCKTIME = 0
SEGWIT_V0_WITVER = 0
SEGWIT_V1_WITVER = 1
DEFAULT_SEQUENCE = 4294967295
DEFAULT_NETWORK = NetworkType.MAIN
DEFAULT_SERVICE_TIMEOUT = 10
EMPTY_SEQUENCE = 0
NEGATIVE_SATOSHI = -1
HASH160_LENGTH = 20
SHA256_LENGTH = SCHNORR_COMPRESSED_PUBKEY_LENGTH = 32

SEPARATORS = {
    'default': {
        b'\x4c': 1,
        b'\x4d': 2,
        b'\x4e': 4
    },
    'increased': {
        b'\xfd': 2,
        b'\xfe': 4,
        b'\xff': 8
    }
}
SEPARATORS_REVERSED = {
    'default': {
        1: b'\x4c',
        2: b'\x4d',
        4: b'\x4e'
    },
    'increased': {
        2: b'\xfd',
        4: b'\xfe',
        8: b'\xff'
    }
}

PREFIXES = {
    'wif': {
        NetworkType.MAIN: b'\x80',
        NetworkType.TEST: b'\xef'
    },
    'wif_reversed': {
        b'\x80': NetworkType.MAIN,
        b'\xef': NetworkType.TEST,

        # for Electrum wifs
        #  https://github.com/spesmilo/electrum/blob/3.0.0/RELEASE-NOTES#L42
        b'\x81': NetworkType.MAIN,
        b'\x82': NetworkType.MAIN,
        b'\x83': NetworkType.MAIN,
        b'\x84': NetworkType.MAIN,
        b'\x85': NetworkType.MAIN,
        b'\x86': NetworkType.MAIN,
        b'\x87': NetworkType.MAIN
    },
    'public_key': {
        'compressed': {
            'even': b'\x02',
            'odd': b'\x03'
        },
        'uncompressed': b'\x04'
    },
    'legacy': {
        AddressType.P2PKH: {
            NetworkType.MAIN: b'\x00',
            NetworkType.TEST: b'\x6f'
        },
        AddressType.P2SH_P2WPKH: {
            NetworkType.MAIN: b'\x05',
            NetworkType.TEST: b'\xc4'
        }
    },
    'legacy_reversed': {
        b'\x00': (AddressType.P2PKH, NetworkType.MAIN),
        b'\x6f': (AddressType.P2PKH, NetworkType.TEST),
        b'\x05': (AddressType.P2SH_P2WPKH, NetworkType.MAIN),
        b'\xc4': (AddressType.P2SH_P2WPKH, NetworkType.TEST)
    },
    'bech32': {
        'separator': '1',
        'hrp': {
            NetworkType.MAIN: 'bc',
            NetworkType.TEST: 'tb'
        },
        'hrpsep': {
            NetworkType.MAIN: 'bc1',
            NetworkType.TEST: 'tb1'
        }
    }
}

SIGHASHES = {
    'all': 0x01,
    'none': 0x02,
    'single': 0x03,
    'anyonecanpay': 0x80
}
