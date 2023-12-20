from collections.abc import Iterable
from typing import Iterable, Iterator, Optional, SupportsIndex, overload

from btclib.const import OP_CODES, CODE_OPS
from btclib.utils import dint, pprint_class
from btclib import exceptions


type InputItem = str | bytes | list[int]


def validate(item: InputItem) -> Optional[str]:
    match item:
        case _ if not isinstance(item, (str, bytes, list)):
            raise exceptions.InvalidInputScriptData(type(item))

        case _ if not len(item):  # empty
            return None

        case list():  # list[int]
            return bytes(item).hex()

        case str() if item.startswith('OP_'):  # opcode
            if item not in OP_CODES:
                raise ValueError(f'unknown opcode: {item}')

            return item

        case str():  # hex
            if len(item) % 2 > 0:
                raise exceptions.HexLengthMustBeMultipleTwo

            try:
                bytes.fromhex(item)
            except ValueError:
                raise exceptions.InvalidHexOrOpcode(item) from None
            
            return item

        case bytes():  # bytes
            return item.hex()


def validator(script: Iterable[InputItem]) -> Iterator[str]:
    for item in script:
        valid = validate(item)
        if not valid:
            continue
        yield valid


class Script(list[str]):
    def __init__(self, *data: InputItem) -> None:
        super().__init__(validator(data))

    @classmethod
    def deserialize(cls, raw: InputItem, *, segwit: bool = False,
                 max_items: Optional[int] = None) -> 'Script':
        script = []
        data = bytes.fromhex(raw) if isinstance(raw, str) else bytes(raw) if isinstance(raw, list) else raw

        count = 0
        while len(data) > 0 and (max_items is None or count < max_items):
            fb = data[0:1]
            op = CODE_OPS.get(fb)

            # if <opcode> <data>
            if op and not segwit:
                item, size = op, 1

            # if <size> <opcode/bytes>
            else:
                size, data = dint.unpack(data, increased_separator=segwit)
                item = data[:size]

                # if <opcode size> <opcode> <data>
                op = 'OP_0' if size == 0 else CODE_OPS.get(item) if size == 1 else None
                item = op if op is not None else item

            script.append(item)
            data = data[size:]
            count += 1

        return cls(*script)

    def is_empty(self) -> bool:
        return not len(self)

    def serialize(self, *, segwit: bool = False) -> bytes:
        b = b''

        for item in self:
            match item:
                case '00' | 'OP_0':
                    b += b'\x00'

                case _ if item.startswith('OP_'):
                    # <op size> + <op> if segwit else <op>
                    b += (b'\x01' if segwit else b'') + OP_CODES[item]

                case _:
                    item = bytes.fromhex(item)
                    b += dint(len(item)).pack(increased_separator=segwit) + item

        return b

    def append(self, __object: InputItem) -> None:
        _object = validate(__object)
        return super().append(_object) if _object else None

    def extend(self, __iterable: Iterable[InputItem]) -> None:
        return super().extend(validator(__iterable))
    
    def insert(self, __index: SupportsIndex, __object: InputItem) -> None:
        _object = validate(__object)
        return super().insert(__index, _object) if _object else None
    
    def copy(self) -> 'Script':
        return Script(*super().copy())

    def __repr__(self) -> str:
        return pprint_class(self, args=self)

    def __eq__(self, other: 'Script') -> bool:
        if not isinstance(other, Script):
            return False
        return super().__eq__(other)

    def __add__(self, __object: 'Script') -> 'Script':
        if not isinstance(__object, Script):
            raise TypeError(f'can only concatenate Script (not "{type(__object).__name__}") to Script')
        return Script(*self, *__object)

    def __iadd__(self, __value: Iterable[InputItem]) -> 'Script':
        return super().__iadd__(validator(__value))

    @overload
    def __setitem__(self, __key: SupportsIndex, __value: InputItem) -> None: ...
    @overload
    def __setitem__(self, __key: slice, __value: Iterable[InputItem]) -> None: ...
    def __setitem__(self, __key, __value) -> None:
        if isinstance(__key, SupportsIndex):
            return super().__setitem__(__key, __v) if (__v := validate(__value)) else None
        if isinstance(__key, slice):
            return super().__setitem__(__key, validator(__value))
        raise TypeError(f'Script indices must be integers or slices, not {type(__key).__name__}')
