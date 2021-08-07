from base58check import b58decode
from hashlib import sha256
from decimal import Decimal

import bech32
from const import PREFIXES


def int2bytes(_i: int) -> bytes:
    _h = '%0.2x' % _i
    return bytes.fromhex(('' if len(_h) % 2 == 0 else '0') + _h)


def bytes2int(_bytes: bytes) -> int:
    return int(_bytes.hex(), 16)


def get_2sha256(bytes_: bytes) -> bytes:
    return sha256(sha256(bytes_).digest()).digest()


def get_address_network(address: str) -> str:

    if address.startswith(('1', '3', 'bc')):
        return 'mainnet'

    elif address.startswith(('2', 'm', 'n', 'tb')):
        return 'testnet'


def get_address_type(address: str) -> str:

    if address.startswith(('1', 'm', 'n')):
        return 'P2PKH'

    elif address.startswith(('2', '3')):
        return 'P2SH'

    elif address.startswith(('bc', 'tb')):
        if len(address) == 42:
            return 'P2WPKH'

        elif len(address) == 62:
            return 'P2WSH'


def validate_address(address: str, address_type: str, address_network: str) -> bool:
    real_address_type = get_address_type(address)

    if real_address_type != address_type or get_address_network(address) != address_network:
        return False

    if real_address_type in ('P2PKH', 'P2SH'):

        if not 26 <= len(address) <= 35:
            return False

        try:
            address_bytes = b58decode(address.encode('utf-8'))
            address_checksum = address_bytes[-4:]
            address_hash = sha256(sha256(address_bytes[:-4]).digest()).digest()
        except:
            return False

        if address_hash[:4] != address_checksum:
            return False

    elif real_address_type in ('P2WPKH', 'P2WSH'):
        ver, array = bech32.decode(PREFIXES['bech32'][address_network], address)

        if None in (ver, array):
            return False

    else:
        return False

    return True


def to_satoshis(value: float) -> int:
    return int(value * 100000000)


def to_bitcoins(value: int) -> Decimal:
    return Decimal(value) / 100000000
