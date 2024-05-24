from typing import cast, overload, Self, Literal, Iterable, Iterator, Optional, SupportsIndex

from btclib.const import OP_CODES, CODE_OPS
from btclib.utils import varint, pprint_class
from btclib import exceptions


type InputItem = str | bytes | list[int]


def validate(item: InputItem) -> Optional[str]:
    """
    :param item: hex/opcode/bytes/list of bytes
    """
    match item:
        case _ if not isinstance(item, (str, bytes, list)):
            raise TypeError(f'str/bytes/list[int] expected, {type(item)} received')

        case _ if not len(item):
            return None

        case list():  # list[int]
            return bytes(item).hex()

        case str() if item.startswith('OP_'):  # opcode
            if item not in OP_CODES:
                raise ValueError(f'unknown opcode \'{item}\'')
            return item

        case str():  # hex
            assert not len(item) % 2, 'hex expected, his length multiple of two'
            try:
                bytes.fromhex(item)
            except ValueError:
                raise exceptions.InvalidHexOrOpcode(item) from None
            return item

        case bytes():  # bytes
            return item.hex()


def validator(script: Iterable[InputItem]) -> Iterator[str]:
    for item in script:
        if not (v := validate(item)):
            continue
        yield v


class Script(list[str]):
    @overload
    def __init__(self,
                 *data: InputItem,
                 _validation: Literal[True] = True,
                 _frozen: Optional[bytes] = None) -> None: ...

    @overload
    def __init__(self,
                 *data: Iterable[str],
                 _validation: Literal[False],
                 _frozen: Optional[bytes] = None) -> None: ...

    def __init__(self,
                 *data: InputItem | Iterable[str],
                 _validation: bool = True,
                 _frozen: Optional[bytes] = None) -> None:
        super().__init__(validator(cast(tuple[InputItem], data)) if _validation else cast(Iterable[str], data))
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
        script: list[str] = []
        data = bytes.fromhex(raw) if isinstance(raw, str) else bytes(raw) if isinstance(raw, list) else raw
        _frozen = data if freeze else None

        count = 0
        while len(data) > 0 and (length is None or count < length):
            # if <opcode> <...>
            if not segwit and (op := CODE_OPS.get(data[:1])):
                item, size = op, 1

            # if <size> <opcode/bytes> <...>
            else:
                size, data = varint.unpack(data, increased_separator=segwit)
                b = data[:size]

                match size:
                    case 0:
                        item = 'OP_0'
                    case 1:
                        item = CODE_OPS.get(b, b.hex())
                    case _:
                        item = b.hex()

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
            match item:
                case '00' | 'OP_0':
                    b += b'\x00'

                case _ if item.startswith('OP_'):
                    # <op size> + <op> if segwit else <op>
                    b += (b'\x01' if segwit else b'') + OP_CODES[item]

                case _:
                    item = bytes.fromhex(item)
                    b += varint(len(item)).pack(increased_separator=segwit) + item

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
        return pprint_class(self, args=self)

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
