import json
import hashlib
from decimal import Decimal
from abc import ABC, abstractmethod
from typing import Any, Callable, Iterable, Literal, Optional, Self, \
                   overload, Protocol, runtime_checkable, Mapping

from btclib.const import SEPARATORS, SEPARATORS_REVERSED


byteorder_T = Literal['little', 'big']


@runtime_checkable
class SupportsDump(Protocol):  # abstract class actually
    @abstractmethod
    def as_dict(self) -> dict:
        ...

    def as_json(self, indent: Optional[int] = None, **kwargs) -> str:
        return json.dumps(self.as_dict(), indent=indent, **kwargs)


@runtime_checkable
class SupportsSerialize(Protocol):
    @abstractmethod
    def serialize(self) -> str | bytes:
        ...


@runtime_checkable
class SupportsCopy(Protocol):
    @abstractmethod
    def copy(self) -> Self:
        ...


@runtime_checkable
class SupportsAmount(Protocol):
    amount: int = NotImplemented


@runtime_checkable
class SupportsCopyAndAmount(SupportsCopy, SupportsAmount, Protocol):
    ...


class ioList[T: SupportsCopyAndAmount](list[T]):
    @property
    def amount(self) -> int:
        return sum(x.amount for x in self)

    def copy(self) -> list[T]:
        return ioList(i.copy() for i in self)


class TypeConverter[expected_T, converted_T]:  # Descriptor
    """
    A descriptor that converts the type that is assigned to an attribute to the set type
    Example: "var = <value>" to "var = __class(<value>)" or "var = __converter(<value>)"

    Usage:
        x: TypeConverter[Iterable[int], int] = TypeConverter(int, sum)
    """
    @overload
    def __init__(self,
                 __class: type[converted_T],
                 __converter: Optional[Callable[[Any], Optional[converted_T]]] = None,
                 *,
                 optional: Literal[True]) -> None: ...

    @overload
    def __init__(self,
                 __class: type[converted_T],
                 __converter: Optional[Callable[[Any], converted_T]] = None,
                 *,
                 optional: Literal[False] = False) -> None: ...

    def __init__(self,
                 __class: type[converted_T],
                 __converter: Optional[Callable[[Any], Optional[converted_T] | converted_T]] = None,
                 *,
                 optional: bool = False) -> None:
        """
        :param __class: The type of the object should be
        :param __converter: A function (or something Callable) called to convert received object to type in __class
        :param optional: Can the attribute be optional (equal to None)
        """
        self.cls = __class
        self.converter = __converter
        self.optional = optional

    def __set_name__(self, owner: Any, name: Any) -> None:
        self.name = name

    @overload
    def __get__(self, instance: None, owner: None) -> 'TypeConverter': ...

    @overload
    def __get__(self, instance: Any, owner: Any) -> converted_T: ...

    def __get__(self, instance: Optional[Any], owner: Optional[Any]) -> 'TypeConverter' | converted_T:
        return self if instance is None else instance.__dict__[self.name]

    def __set__(self, instance: Any, value: expected_T | converted_T) -> None:
        if isinstance(value, self.cls) or value is None and self.optional:
            v: Optional[converted_T] = value
        elif self.converter:
            v: Optional[converted_T] = self.converter(value)
            assert v is not None or self.optional, 'converter can\'t return None if optional=False'
        else:
            v = self.cls(value)  # type: ignore

        instance.__dict__[self.name] = v


class _int(int, ABC):
    size: int = NotImplemented  # byte size
    _signed: bool = NotImplemented

    __integer_overflow_error = lambda _, i, s: OverflowError(f'received int ({i}) is greater than the max size ({s} bytes)')

    def __init__(self, *args, **kwargs) -> None:
        try:
            super().to_bytes(self.size, 'big', signed=self._signed)
        except OverflowError:
            raise self.__integer_overflow_error(self, self.size) from None

    @classmethod
    def unpack(cls, value: bytes, byteorder: byteorder_T = 'little') -> Self:
        if len(value) > cls.size:
            raise cls.__integer_overflow_error(cls, value, cls.size)

        return cls(int.from_bytes(value, byteorder, signed=cls._signed))

    def pack(self, byteorder: byteorder_T = 'little') -> bytes:
        return super().to_bytes(self.size, byteorder, signed=self._signed)


class _signedint(_int):
    _signed = True


class int32(_signedint):
    size = 4


class int64(_signedint):
    size = 8


class _uint(_int):
    _signed = False

    def __init__(self, *args, **kwargs) -> None:
        assert self >= 0, f'unsigned int received signed int (for {self} use sint)'
        super().__init__(self)


class uint32(_uint):
    size = 4


class uint64(_uint):
    size = 8


class varint(int):
    def __init__(self, *args, **kwargs) -> None:
        assert self >= 0, f'varint only supports unsigned int, but {self} received'

    @classmethod
    def unpack(cls, raw_data: bytes, byteorder: byteorder_T = 'little', *,
               increased_separator: bool = True) -> tuple['varint', bytes]:
        """
        Receives full data, decoding beginning int, return tuple[int, other_data[int_size:]].
        Most commonly used to get the size of the following data.

        Example raw_data:

                             fdc003/4dc003          fc2ed1a0fc2ed1a0fc2ed1a0fc2ed1a0 * 60
                   <segwit/non-segwit data size int>               <data>

         return   ->    int(fdc003/4dc003)    ,    fc2ed1a0fc2ed1a0fc2ed1a0fc2ed1a0 * 60
                   <segwit/non-segwit data size int>          <raw_data[size:]>

        """
        # pop fist byte
        fb = raw_data[:1]
        fbint = fb[0]
        raw_data = raw_data[1:]

        if fbint > 0x4e:
            increased_separator = True

        if fbint < (0xfd if increased_separator else 0x4c):
            return cls(fbint), raw_data

        sizelength = SEPARATORS['increased' if increased_separator else 'default'][fb]
        return cls(bytes2int(raw_data[:sizelength], byteorder)), raw_data[sizelength:]

    def pack(self, byteorder: byteorder_T = 'little', *, increased_separator: bool = True) -> bytes:
        sizeb = int2bytes(self, byteorder)

        if self < (253 if increased_separator else 76):
            return sizeb

        sizelength = len(sizeb)

        if sizelength > (8 if increased_separator else 4):
            raise ValueError(f'int too large for pack ({self}, increased_separator={increased_separator})')

        separator = b''
        for new_size, sep in SEPARATORS_REVERSED['increased' if increased_separator else 'default'].items():
            if sizelength <= new_size:
                sizelength, separator = new_size, sep
                break

        return separator + self.to_bytes(sizelength, byteorder)


def r160(d: bytes) -> bytes:
    h = hashlib.new('ripemd160')
    h.update(d)
    return h.digest()


def sha256(d: bytes) -> bytes:
    return hashlib.sha256(d).digest()


def d_sha256(d: bytes) -> bytes:  # double sha256
    return sha256(sha256(d))


def op_hash160(d: bytes):
    return r160(sha256(d))


def int2bytes(v: int, byteorder: byteorder_T = 'big', *, signed: bool = False) -> bytes:
    """
    Convert int to bytes representation with minimum possible byte size
    :param v: value
    :param byteorder: byteorder
    :param signed: if signed int
    """
    if signed:
        blength  = (-v - 1 if v < 0 else v).bit_length() + 1  # +1 sign bit
    else:
        blength = v.bit_length() or 1  # 1 if v is zero
    return v.to_bytes((blength + 7) // 8, byteorder, signed=signed)


def bytes2int(value: bytes, byteorder: byteorder_T = 'big', *, signed: bool = False) -> int:
    return int.from_bytes(value, byteorder, signed=signed)


def get_magic_hash(message: str) -> bytes:
    pref = b'Bitcoin Signed Message:\n'
    messageb = message.encode('utf8')
    return d_sha256(b''.join([
        int2bytes(len(pref)),
        pref,
        int2bytes(len(message)),
        messageb
    ]))


def to_satoshis(value: float) -> int:
    return int(Decimal(str(value)) * 100000000)


def to_bitcoins(value: int) -> float:
    return float(Decimal(str(value)) / 100000000)


def pprint_class(class_or_instance: type | Any,
                 args: Iterable = (),
                 kwargs: dict[Any, Any] = {},
                 classmethod: Optional[str] = None) -> str:
    cls = class_or_instance if isinstance(class_or_instance, type) else type(class_or_instance)
    name = cls.__qualname__
    pv = lambda v: repr(v) if not isinstance(v, str) or v == '' else v
    akw = ', '.join([
        *(f'{pv(v)}' for v in args),
        *(f'{k}={pv(v)}' for k, v in kwargs.items())
    ])
    return f'{name}{f'.{classmethod}' if classmethod else ''}({akw})'
