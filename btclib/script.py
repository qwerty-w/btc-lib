from typing import cast, overload, Self, Literal, Iterable, Iterator, Optional, SupportsIndex

from btclib.const import OP_CODES, CODE_OPS
from btclib.utils import varint, pprint_class
from btclib import exceptions


type InputItem = bytes | str | Iterable[int]


def validate(item: InputItem, *, opcodes: bool = True) -> Optional[bytes]:
    """
    :param item: bytes/hex/opcode (if opcodes)/byte array
    :param opcodes: validate opcodes
    :param 
    """
    match item:
        case str() | bytes() if not len(item):
            return None

        case str() if item.startswith('OP_') and opcodes:  # opcode
            if not (v := OP_CODES.get(item)):
                raise ValueError(f'unknown opcode \'{item}\'')
            return v

        case str():  # hex
            assert not len(item) % 2, 'hex expected, his length multiple of two'
            try:
                return bytes.fromhex(item)
            except ValueError:
                raise exceptions.InvalidHexOrOpcode(item) from None

        case bytes():
            return item

        case Iterable():
            return bytes(item) or None  # Iterable[int] can be empty

        case _:
            raise TypeError(f'str/bytes/Iterable[int] expected, {type(item)} received')


def validator(script: Iterable[InputItem]) -> Iterator[bytes]:
    for item in script:
        if not (v := validate(item)):
            continue
        yield v


class Script(list[bytes]):
    @overload
    def __init__(self,
                 *data: InputItem,
                 _validation: Literal[True] = True,
                 _frozen: Optional[bytes] = None) -> None: ...

    @overload
    def __init__(self,
                 *data: bytes,
                 _validation: Literal[False],
                 _frozen: Optional[bytes] = None) -> None: ...

    def __init__(self,
                 *data: InputItem | Iterable[bytes],
                 _validation: bool = True,
                 _frozen: Optional[bytes] = None) -> None:
        super().__init__(validator(cast(tuple[InputItem], data)) if _validation else cast(tuple[bytes], data))
        self._frozen = _frozen

    @classmethod
    def deserialize(cls, raw: InputItem, *, segwit: bool = False,
                    length: Optional[int] = None, freeze: bool = False) -> Self:
        """
        :param raw: hex/bytes/list of bytes
        :param segwit: 
        :param length: items count
        :param freeze: make script frozen: script .serialize() will returns deserialized value
                       until the first internal change (need for coinbase transactions in
                       which the script input can be arbitrary)
        """
        script: list[bytes] = []
        data = validate(raw, opcodes=False) or b''
        _frozen = data if freeze else None

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

        return cls(*script, _validation=False, _frozen=_frozen)

    def is_frozen(self) -> bool:
        return self._frozen is not None

    def is_empty(self) -> bool:
        return not len(self)

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

    def append(self, instance: InputItem) -> None:
        self._frozen = None
        return super().append(v) if (v := validate(instance)) else None

    def extend(self, iterable: Iterable[InputItem]) -> None:
        self._frozen = None
        return super().extend(validator(iterable))
    
    def insert(self, index: SupportsIndex, instance: InputItem) -> None:
        self._frozen = None
        return super().insert(index, v) if (v := validate(instance)) else None
    
    def copy(self) -> 'Script':
        return type(self)(*self, _validation=False)

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

    def __iadd__(self, instance: Iterable[InputItem]) -> 'Script':
        self._frozen = None
        return super().__iadd__(validator(instance))

    @overload
    def __setitem__(self, key: SupportsIndex, instance: InputItem) -> None:
        ...
    @overload
    def __setitem__(self, key: slice, instance: Iterable[InputItem]) -> None:
        ...
    def __setitem__(self, key, instance) -> None:
        self._frozen = None
        match key:
            case SupportsIndex():
                return super().__setitem__(key, v) if (v := validate(instance)) else None
            case slice():
                return super().__setitem__(key, validator(instance))
            case _:
                raise TypeError(f'indices must be integers or slices, not {type(key).__name__}')
