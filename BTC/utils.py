from base58check import b58decode
from hashlib import sha256
from decimal import Decimal

import bech32
from const import PREFIXES, SEPARATORS


def split_size(raw_data: bytes, endian: str = 'little',
               *, increased_separator: bool = False) -> tuple[int, bytes]:
    """
    Decoding size-int, return tuple[size, raw_data[size:]].

    Example raw_data:

             fdc003/4dc003          fc2ed1a0fc2ed1a0fc2ed1a0fc2ed1a0 * 60
     <segwit/non-segwit data size>                <data>

     return   ->    (int(fdc003/4dc003)  ,   fc2ed1a0fc2ed1a0fc2ed1a0fc2ed1a0 * 60
                <segwit-non-segwit int size>          <raw_data[size:]>

    """
    # pop fist byte
    first_byte = raw_data[0:1]
    first_byte_int = first_byte[0]
    raw_data = raw_data[1:]

    if first_byte_int > 78:
        increased_separator = True

    if first_byte_int < (253 if increased_separator else 76):
        return first_byte_int, raw_data

    data_start = SEPARATORS['increased' if increased_separator else 'default'][first_byte]
    data_size = bytes2int(raw_data[:data_start], endian)
    return data_size, raw_data[data_start:]


def int2bytes(value: int, endian: str = 'big') -> bytes:
    h = '%0.2x' % value
    data = bytes.fromhex(('' if len(h) % 2 == 0 else '0') + h)
    return data if endian == 'big' else data[::-1]


def bytes2int(value: bytes, endian: str = 'big') -> int:  # value must be in big endian
    bytes_ = value if endian == 'big' else value[::-1]
    return int(bytes_.hex(), 16)


def get_2sha256(data: bytes) -> bytes:
    return sha256(sha256(data).digest()).digest()


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
            address_hash = get_2sha256(address_bytes[:-4])
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
