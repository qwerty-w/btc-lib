from enum import IntEnum
from typing import cast, overload, Self, Literal, Iterable, Iterator, Optional, SupportsIndex

from btclib.utils import varint, pprint_class


class opcode(IntEnum):
    # push value
    OP_0 = 0x00
    OP_FALSE = OP_0
    OP_PUSHDATA1 = 0x4c
    OP_PUSHDATA2 = 0x4d
    OP_PUSHDATA4 = 0x4e
    OP_1NEGATE = 0x4f
    OP_RESERVED = 0x50
    OP_1 = 0x51
    OP_TRUE = OP_1
    OP_2 = 0x52
    OP_3 = 0x53
    OP_4 = 0x54
    OP_5 = 0x55
    OP_6 = 0x56
    OP_7 = 0x57
    OP_8 = 0x58
    OP_9 = 0x59
    OP_10 = 0x5a
    OP_11 = 0x5b
    OP_12 = 0x5c
    OP_13 = 0x5d
    OP_14 = 0x5e
    OP_15 = 0x5f
    OP_16 = 0x60

    # control
    OP_NOP = 0x61
    OP_VER = 0x62
    OP_IF = 0x63
    OP_NOTIF = 0x64
    OP_VERIF = 0x65
    OP_VERNOTIF = 0x66
    OP_ELSE = 0x67
    OP_ENDIF = 0x68
    OP_VERIFY = 0x69
    OP_RETURN = 0x6a

    # stack ops
    OP_TOALTSTACK = 0x6b
    OP_FROMALTSTACK = 0x6c
    OP_2DROP = 0x6d
    OP_2DUP = 0x6e
    OP_3DUP = 0x6f
    OP_2OVER = 0x70
    OP_2ROT = 0x71
    OP_2SWAP = 0x72
    OP_IFDUP = 0x73
    OP_DEPTH = 0x74
    OP_DROP = 0x75
    OP_DUP = 0x76
    OP_NIP = 0x77
    OP_OVER = 0x78
    OP_PICK = 0x79
    OP_ROLL = 0x7a
    OP_ROT = 0x7b
    OP_SWAP = 0x7c
    OP_TUCK = 0x7d

    # splice ops
    OP_CAT = 0x7e
    OP_SUBSTR = 0x7f
    OP_LEFT = 0x80
    OP_RIGHT = 0x81
    OP_SIZE = 0x82

    # bit logic
    OP_INVERT = 0x83
    OP_AND = 0x84
    OP_OR = 0x85
    OP_XOR = 0x86
    OP_EQUAL = 0x87
    OP_EQUALVERIFY = 0x88
    OP_RESERVED1 = 0x89
    OP_RESERVED2 = 0x8a

    # numeric
    OP_1ADD = 0x8b
    OP_1SUB = 0x8c
    OP_2MUL = 0x8d
    OP_2DIV = 0x8e
    OP_NEGATE = 0x8f
    OP_ABS = 0x90
    OP_NOT = 0x91
    OP_0NOTEQUAL = 0x92

    OP_ADD = 0x93
    OP_SUB = 0x94
    OP_MUL = 0x95
    OP_DIV = 0x96
    OP_MOD = 0x97
    OP_LSHIFT = 0x98
    OP_RSHIFT = 0x99

    OP_BOOLAND = 0x9a
    OP_BOOLOR = 0x9b
    OP_NUMEQUAL = 0x9c
    OP_NUMEQUALVERIFY = 0x9d
    OP_NUMNOTEQUAL = 0x9e
    OP_LESSTHAN = 0x9f
    OP_GREATERTHAN = 0xa0
    OP_LESSTHANOREQUAL = 0xa1
    OP_GREATERTHANOREQUAL = 0xa2
    OP_MIN = 0xa3
    OP_MAX = 0xa4

    OP_WITHIN = 0xa5

    # crypto
    OP_RIPEMD160 = 0xa6
    OP_SHA1 = 0xa7
    OP_SHA256 = 0xa8
    OP_HASH160 = 0xa9
    OP_HASH256 = 0xaa
    OP_CODESEPARATOR = 0xab
    OP_CHECKSIG = 0xac
    OP_CHECKSIGVERIFY = 0xad
    OP_CHECKMULTISIG = 0xae
    OP_CHECKMULTISIGVERIFY = 0xaf

    # expansion
    OP_NOP1 = 0xb0
    OP_CHECKLOCKTIMEVERIFY = 0xb1
    OP_NOP2 = OP_CHECKLOCKTIMEVERIFY
    OP_CHECKSEQUENCEVERIFY = 0xb2
    OP_NOP3 = OP_CHECKSEQUENCEVERIFY
    OP_NOP4 = 0xb3
    OP_NOP5 = 0xb4
    OP_NOP6 = 0xb5
    OP_NOP7 = 0xb6
    OP_NOP8 = 0xb7
    OP_NOP9 = 0xb8
    OP_NOP10 = 0xb9

    OP_RETURN_186 = 0xba
    OP_RETURN_187 = 0xbb
    OP_RETURN_188 = 0xbc
    OP_RETURN_189 = 0xbd
    OP_RETURN_190 = 0xbe
    OP_RETURN_191 = 0xbf
    OP_RETURN_192 = 0xc0
    OP_RETURN_193 = 0xc1
    OP_RETURN_194 = 0xc2
    OP_RETURN_195 = 0xc3
    OP_RETURN_196 = 0xc4
    OP_RETURN_197 = 0xc5
    OP_RETURN_198 = 0xc6
    OP_RETURN_199 = 0xc7
    OP_RETURN_200 = 0xc8
    OP_RETURN_201 = 0xc9
    OP_RETURN_202 = 0xca
    OP_RETURN_203 = 0xcb
    OP_RETURN_204 = 0xcc
    OP_RETURN_205 = 0xcd
    OP_RETURN_206 = 0xce
    OP_RETURN_207 = 0xcf
    OP_RETURN_208 = 0xd0
    OP_RETURN_209 = 0xd1
    OP_RETURN_210 = 0xd2
    OP_RETURN_211 = 0xd3
    OP_RETURN_212 = 0xd4
    OP_RETURN_213 = 0xd5
    OP_RETURN_214 = 0xd6
    OP_RETURN_215 = 0xd7
    OP_RETURN_216 = 0xd8
    OP_RETURN_217 = 0xd9
    OP_RETURN_218 = 0xda
    OP_RETURN_219 = 0xdb
    OP_RETURN_220 = 0xdc
    OP_RETURN_221 = 0xdd
    OP_RETURN_222 = 0xde
    OP_RETURN_223 = 0xdf
    OP_RETURN_224 = 0xe0
    OP_RETURN_225 = 0xe1
    OP_RETURN_226 = 0xe2
    OP_RETURN_227 = 0xe3
    OP_RETURN_228 = 0xe4
    OP_RETURN_229 = 0xe5
    OP_RETURN_230 = 0xe6
    OP_RETURN_231 = 0xe7
    OP_RETURN_232 = 0xe8
    OP_RETURN_233 = 0xe9
    OP_RETURN_234 = 0xea
    OP_RETURN_235 = 0xeb
    OP_RETURN_236 = 0xec
    OP_RETURN_237 = 0xed
    OP_RETURN_238 = 0xee
    OP_RETURN_239 = 0xef
    OP_RETURN_240 = 0xf0
    OP_RETURN_241 = 0xf1
    OP_RETURN_242 = 0xf2
    OP_RETURN_243 = 0xf3
    OP_RETURN_244 = 0xf4
    OP_RETURN_245 = 0xf5
    OP_RETURN_246 = 0xf6
    OP_RETURN_247 = 0xf7
    OP_RETURN_248 = 0xf8
    OP_RETURN_249 = 0xf9
    OP_RETURN_250 = 0xfa
    OP_RETURN_251 = 0xfb
    OP_RETURN_252 = 0xfc
    OP_RETURN_253 = 0xfd
    OP_RETURN_254 = 0xfe

    OP_INVALIDOPCODE = 0xff

    def serialize(self) -> bytes:
        return bytes([self])


# initial arguments type: can be raw bytes, string hex, string opcode or
# iterable bytes in int representation (like bytearray, memoryview and etc)
type init_T = opcode | bytes | str | Iterable[int]
# internal script items type
type inner_T = opcode | bytes

@overload
def validate(item: init_T, *, opcodes: Literal[True] = True) -> inner_T:
    ...
@overload
def validate(item: init_T, *, opcodes: Literal[False]) -> bytes:
    ...
def validate(item: init_T, *, opcodes: bool = True) -> inner_T:
    """
    :param item: bytes/hex/opcode (if opcodes)/byte array
    :param opcodes: Handle opcodes
    """
    nooperr = TypeError('opcode not allowed in this context')
    match item:
        case opcode():
            if not opcodes:
                raise nooperr
            return item

        case str() if item.startswith('OP_'):
            if not opcodes:
                raise nooperr
            if not (v := opcode.__members__.get(item)):
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


def validator(script: Iterable[init_T]) -> Iterator[inner_T]:
    for item in script:
        yield validate(item)


class Script(list[inner_T]):
    @overload
    def __init__(self,
                 *data: init_T,
                 validation: Literal[True] = True,
                 frozen: Optional[bytes] = None) -> None: ...

    @overload
    def __init__(self,
                 *data: inner_T,
                 validation: Literal[False],
                 frozen: Optional[bytes] = None) -> None: ...

    def __init__(self,
                 *data: init_T | inner_T,
                 validation: bool = True,
                 frozen: Optional[bytes] = None) -> None:
        super().__init__(validator(cast(tuple[init_T], data)) if validation else cast(tuple[inner_T], data))
        self._frozen = frozen

    @classmethod
    def deserialize(cls, raw: bytes | str | Iterable[int], *, segwit: bool = False,
                    length: Optional[int] = None, freeze: bool = False) -> Self:
        """
        :param raw: Hex, bytes or list of bytes (like init_T but exclude opcodes)
        :param segwit: If it's a witness
        :param length: Maximum items count
        :param freeze: Make script frozen: script .serialize() will returns saved serialized value
                       until the first internal change (need for coinbase transactions in which
                       the script input can be arbitrary)
        """
        script: list[inner_T] = []
        data = validate(raw, opcodes=False) or b''
        frozen = data if freeze else None

        count = 0
        while len(data) > 0 and (length is None or count < length):
            fbint = data[0]

             # if <opcode> <...>
            if not segwit and fbint == opcode.OP_0.value or fbint > opcode.OP_PUSHDATA4:
                item, size = opcode(fbint), 1

            # if <varint size> <bytes> <...>
            else:
                size, data = varint.unpack(data, increased_separator=segwit)
                item = data[:size]

            script.append(item)
            data = data[size:]
            count += 1

        return cls(*script, validation=False, frozen=frozen)

    @property
    def frozen(self) -> bool:
        return self._frozen is not None

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

    def copy(self) -> Self:
        return type(self)(*self, validation=False)

    def serialize(self, *, segwit: bool = False) -> bytes:
        if self.frozen:
            return cast(bytes, self._frozen)

        b = b''
        for item in self:
            if isinstance(item, opcode):
                item = item.serialize()

                if not segwit:
                    b += item
                    continue

            b += varint(len(item)).pack(increased_separator=segwit) + item
        return b

    def __repr__(self) -> str:
        return pprint_class(self, args=[
            item.name if isinstance(item, opcode) else item.hex()
            for item in self
        ])

    def __eq__(self, other: 'Script') -> bool:
        if not isinstance(other, Script):
            return False
        return super().__eq__(other)

    def __add__(self, instance: 'Script') -> Self:
        if not isinstance(instance, Script):
            raise TypeError(f'can only concatenate Script (not "{type(instance).__name__}") to Script')
        return type(self)(*self, *instance, validation=False)

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
