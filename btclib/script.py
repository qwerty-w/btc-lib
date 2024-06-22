from typing import cast, overload, Self, Literal, Iterable, Iterator, Optional, SupportsIndex

from btclib.const import OP_CODES, CODE_OPS
from btclib.utils import varint, pprint_class


# initial arguments type: can be raw bytes, string hex, string opcode or
# iterable bytes in int representation (like bytearray, memoryview and etc)
type init_T = bytes | str | Iterable[int]


def validate(item: init_T, *, opcodes: bool = True) -> bytes:
    """
    :param item: bytes/hex/opcode (if opcodes)/byte array
    :param opcodes: Handle opcodes
    """
    match item:
        case str() if item.startswith('OP_') and opcodes:  # opcode
            if not (v := OP_CODES.get(item)):
                raise LookupError(f'unknown opcode \'{item}\'')
            return v

        case str():  # hex
            assert not len(item) % 2, 'string hex expected, his length multiple of two'
            return bytes.fromhex(item)

        case bytes():
            return item

        case _ if isinstance(item, Iterable):
            return bytes(item)

        case _:
            raise TypeError(f'string hex, bytes or Iterable[int] expected, but {type(item)} received')


def validator(script: Iterable[init_T]) -> Iterator[bytes]:
    for item in script:
        if not (v := validate(item)):
            continue
        yield v


class Script(list[bytes]):
    @overload
    def __init__(self,
                 *data: init_T,
                 validation: Literal[True] = True,
                 frozen: Optional[bytes] = None) -> None: ...

    @overload
    def __init__(self,
                 *data: bytes,
                 validation: Literal[False],
                 frozen: Optional[bytes] = None) -> None: ...

    def __init__(self,
                 *data: init_T | bytes,
                 validation: bool = True,
                 frozen: Optional[bytes] = None) -> None:
        super().__init__(validator(data) if validation else cast(tuple[bytes], data))
        self._frozen = frozen

    @classmethod
    def deserialize(cls, raw: bytes | str | Iterable[int], *, segwit: bool = False,
                    length: Optional[int] = None, freeze: bool = False) -> Self:
        """
        :param raw: Hex, bytes or list of bytes (like init_T but exclude string opcode)
        :param segwit: 
        :param length: Maximum items count
        :param freeze: Make script frozen: script .serialize() will returns deserialized value
                       until the first internal change (need for coinbase transactions in
                       which the script input can be arbitrary)
        """
        script: list[bytes] = []
        data = validate(raw, opcodes=False) or b''
        frozen = data if freeze else None

        count = 0
        while len(data) > 0 and (length is None or count < length):
            # if <opcode> <...>
            if not segwit and (item := data[:1]) in CODE_OPS:
                size = 1

            # if <size> <opcode/bytes> <...>
            else:
                size, data = varint.unpack(data, increased_separator=segwit)
                b = data[:size]
                item = b if size else OP_CODES['OP_0']

            script.append(item)
            data = data[size:]
            count += 1

        return cls(*script, validation=False, frozen=frozen)

    def is_frozen(self) -> bool:
        return self._frozen is not None

    def is_empty(self) -> bool:
        return not len(self)
    
    def unfreeze(self) -> None:
        self._frozen = None

    def append(self, instance: init_T) -> None:
        if v := validate(instance): super().append(v)
        self.unfreeze()

    def extend(self, iterable: Iterable[init_T]) -> None:
        super().extend(validator(iterable))
        self.unfreeze()
    
    def insert(self, index: SupportsIndex, instance: init_T) -> None:
        if v := validate(instance): super().insert(index, v)
        self.unfreeze()
    
    def copy(self) -> 'Script':
        return type(self)(*self, validation=False)

    def serialize(self, *, segwit: bool = False) -> bytes:
        if self.is_frozen():
            return cast(bytes, self._frozen)

        b = b''
        for item in self:
            length = len(item)
            if item != OP_CODES['OP_0'] and (segwit or length > 1 or item not in CODE_OPS):
                b += varint(length).pack(increased_separator=segwit)
            b += item
        return b

    def __repr__(self) -> str:
        return pprint_class(self, args=[
            opcode if len(item) == 1 and (opcode := CODE_OPS.get(item)) else item.hex()
            for item in self
        ])

    def __eq__(self, other: 'Script') -> bool:
        if not isinstance(other, Script):
            return False
        return super().__eq__(other)

    def __add__(self, instance: 'Script') -> 'Script':
        if not isinstance(instance, Script):
            raise TypeError(f'can only concatenate Script (not "{type(instance).__name__}") to Script')
        return type(self)(*self, *instance)

    def __iadd__(self, instance: Iterable[init_T]) -> Self:
        rv = super().__iadd__(validator(instance))
        self.unfreeze()
        return rv

    @overload
    def __setitem__(self, key: SupportsIndex, instance: init_T) -> None:
        ...
    @overload
    def __setitem__(self, key: slice, instance: Iterable[init_T]) -> None:
        ...
    def __setitem__(self, key, instance) -> None:
        match key:
            case SupportsIndex():
                if v := validate(instance):
                    super().__setitem__(key, v)
            case slice():
                super().__setitem__(key, validator(instance))
            case _:
                raise TypeError(f'indices must be integers or slices, not {type(key).__name__}')
        self.unfreeze()
