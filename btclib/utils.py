import hashlib
from typing import Any, Iterable, Literal, Optional
from abc import ABC
from base58check import b58decode
from decimal import Decimal

from btclib import bech32
from btclib.const import PREFIXES, SEPARATORS, SEPARATORS_REVERSED, AddressType, NetworkType
from btclib import exceptions


byteorder_T = Literal['little', 'big']


class TypeConverter:  # Descriptor
    """
    Converts "a = <value>" to "a = cls(<value>)"
    """

    def __init__(self, cls: type, *, allow_none: bool = False):
        self.cls = cls
        self.allow_none = allow_none

    def __set_name__(self, owner, name):
        self.name = name

    def __get__(self, instance, owner):
        if instance is None:
            return self

        return instance.__dict__[self.name]

    def __set__(self, instance, value):
        val = self.cls(value) if not (isinstance(value, self.cls) or (value is None and self.allow_none)) else value
        instance.__dict__[self.name] = val


class _int(int, ABC):
    size: int = NotImplemented  # byte size
    _signed: bool = NotImplemented

    def __init__(self, i: int):
        try:
            super().to_bytes(self.size, 'big', signed=self._signed)
        except OverflowError:
            raise exceptions.IntSizeGreaterThanMaxSize(i, self.size) from None

    @classmethod
    def unpack(cls, value: bytes, byteorder: byteorder_T = 'little') -> '_int':
        if len(value) > cls.size:
            raise exceptions.IntSizeGreaterThanMaxSize(value, cls.size)

        return cls(int.from_bytes(value, byteorder, signed=cls._signed))

    def pack(self, byteorder: byteorder_T = 'little') -> bytes:
        return super().to_bytes(self.size, byteorder, signed=self._signed)


class _sint(_int):
    _signed = True


class sint32(_sint):
    size = 4


class sint64(_sint):
    size = 8


class _uint(_int):
    _signed = False

    def __init__(self, i: int):
        if i < 0:
            raise exceptions.UintGotSint(i)

        super().__init__(i)


class uint32(_uint):
    size = 4


class uint64(_uint):
    size = 8


class dint(int):
    def __init__(self, *args, **kwargs):
        if self < 0:
            raise exceptions.DynamicIntOnlySupportsUnsignedInt(self)

    @classmethod
    def unpack(cls, raw_data: bytes, byteorder: byteorder_T = 'little', *,
               increased_separator: bool = True) -> 'tuple[dint, bytes]':
        """
        Receives full data, decoding beginning int, return tuple[int, other_data[int_size:]].
        Most commonly used to get the size of the following data.

        Example raw_data:

                             fdc003/4dc003          fc2ed1a0fc2ed1a0fc2ed1a0fc2ed1a0 * 60
                   <segwit/non-segwit data size int>               <data>

         return   ->    (int(fdc003/4dc003)    ,    fc2ed1a0fc2ed1a0fc2ed1a0fc2ed1a0 * 60
                   <segwit/non-segwit data size int>          <raw_data[size:]>

        """
        # pop fist byte
        first_byte = raw_data[0:1]
        first_byte_int = first_byte[0]
        raw_data = raw_data[1:]

        if first_byte_int > 78:
            increased_separator = True

        if first_byte_int < (253 if increased_separator else 76):
            return cls(first_byte_int), raw_data

        int_size = SEPARATORS['increased' if increased_separator else 'default'][first_byte]
        return cls(bytes2int(raw_data[:int_size], byteorder)), raw_data[int_size:]

    def pack(self, byteorder: byteorder_T = 'little', *, increased_separator: bool = True) -> bytes:
        size_bytes = int2bytes(self, byteorder)

        if self < (253 if increased_separator else 76):
            return size_bytes

        int_size = len(size_bytes)

        if int_size > (8 if increased_separator else 4):
            raise ValueError(f'int too large for pack ({self}, increased_separator={increased_separator})')

        separator = b''
        for new_size, sep in SEPARATORS_REVERSED['increased' if increased_separator else 'default'].items():
            if int_size <= new_size:
                int_size, separator = new_size, sep
                break

        return separator + self.to_bytes(int_size, byteorder)


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def d_sha256(data: bytes) -> bytes:  # double sha256
    return sha256(sha256(data))


def r160(data: bytes) -> bytes:
    h = hashlib.new('ripemd160')
    h.update(data)
    return h.digest()


def int2bytes(value: int, byteorder: byteorder_T = 'big', *, signed: bool = False) -> bytes:
    """
    Uses minimum possible bytes size for integer.
    """
    is_negative = value < 0
    if is_negative:
        signed = True

    size = int((size := value.bit_length() / 8) + (0 if size.is_integer() else 1))  # unsigned size

    if value == 0:
        size = 1

    if signed:
        # max positive/negative values with unsigned size
        max_positive_value = int.from_bytes(b'\xff' * size, 'big') // 2
        max_negative_value = -max_positive_value - 1

        if not is_negative and value > max_positive_value or is_negative and value < max_negative_value:
            size += 1

    return value.to_bytes(size, byteorder, signed=signed)


def bytes2int(value: bytes, byteorder: byteorder_T = 'big', *, signed: bool = False) -> int:
    return int.from_bytes(value, byteorder, signed=signed)


def get_magic_hash(message: str):
    pref = b'Bitcoin Signed Message:\n'
    message_b = message.encode()
    return d_sha256(b''.join([
        int2bytes(len(pref)),
        pref,
        int2bytes(len(message)),
        message_b
    ]))


def get_address_network(address: str) -> Optional[NetworkType]:
    if address.startswith(('1', '3', 'bc')):
        return NetworkType.MAIN

    elif address.startswith(('2', 'm', 'n', 'tb')):
        return NetworkType.TEST


def get_address_type(address: str) -> Optional[AddressType]:
    if address.startswith(('1', 'm', 'n')):
        return AddressType.P2PKH

    elif address.startswith(('2', '3')):
        return AddressType.P2SH_P2WPKH

    elif address.startswith(('bc', 'tb')):
        if len(address) == 42:
            return AddressType.P2WPKH

        elif len(address) == 62:
            return AddressType.P2WSH


def validate_address(address: str, address_type: AddressType, address_network: NetworkType) -> bool:
    real_type = get_address_type(address)

    if real_type != address_type or get_address_network(address) != address_network:
        return False

    if real_type in [AddressType.P2PKH, AddressType.P2SH_P2WPKH]:
        if not 26 <= len(address) <= 35:
            return False

        try:
            b = b58decode(address.encode())
            checksum, h = b[-4:], d_sha256(b[:-4])
        except:
            return False

        if h[:4] != checksum:
            return False

    elif real_type in (AddressType.P2WPKH, AddressType.P2WSH):
        ver, array = bech32.decode(PREFIXES['bech32'][address_network], address)

        if None in (ver, array):
            return False

    else:
        return False

    return True


def to_satoshis(value: float) -> int:
    return int(Decimal(str(value)) * 100000000)


def to_bitcoins(value: int) -> float:
    return float(Decimal(str(value)) / 100000000)


def pprint_class(class_or_instance: type | Any, args: Iterable = (), kwargs: dict[Any, Any] = {}):
    cls = class_or_instance if isinstance(class_or_instance, type) else type(class_or_instance)
    name = cls.__qualname__
    all_args = ', '.join(
        [
            *(f'{value}' for value in args),
            *(f'{arg}={value}' for arg, value in kwargs.items())
        ]
    )
    return f'{name}({all_args})'
