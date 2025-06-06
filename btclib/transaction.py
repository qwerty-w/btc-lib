from collections import OrderedDict
from typing import Iterable, Optional, Self, TypedDict, NotRequired, cast, overload, Literal

from btclib.script import opcode, Script
from btclib.utils import SupportsDump, SupportsSerialize, SupportsCopy, SupportsCopyAndAmount, \
                         ioList, TypeConverter, uint32, int64, varint, d_sha256, op_hash160, \
                         bytes2int, pprint_class
from btclib.address import BaseAddress, PrivateKey, P2PKH, P2SH, P2WPKH, P2WSH, from_pkscript
from btclib.const import DEFAULT_NETWORK, DEFAULT_SEQUENCE, DEFAULT_VERSION, DEFAULT_LOCKTIME, \
                         SIGHASHES, EMPTY_SEQUENCE, NEGATIVE_SATOSHI, AddressType, NetworkType


class UnspentDict[T: str | bytes](TypedDict):
    txid: T
    vout: uint32
    amount: int64
    block: int
    pkscript: T
    address: str


class InputDict[T: str | bytes](TypedDict):  # T: str | bytes = bytes (python3.13)
    txid: T
    vout: uint32
    amount: NotRequired[int]
    script: T
    witness: NotRequired[T]
    address: NotRequired[str]
    sequence: uint32


class OutputDict[T: str | bytes](TypedDict):
    pkscript: T
    amount: int64
    address: NotRequired[str]


class TransactionDict[T: str | bytes](TypedDict):
    inputs: list[InputDict[T]]
    outputs: list[OutputDict[T]]
    version: uint32
    locktime: uint32


class Block(int):
    def is_mempool(self) -> bool:
        return self == -1


class Unspent(SupportsDump):
    vout: TypeConverter[int, uint32] = TypeConverter(uint32)
    amount: TypeConverter[int, int64] = TypeConverter(int64)
    block: TypeConverter[int, Block] = TypeConverter(Block)

    def __init__(self, txid: bytes, vout: int, amount: int, block: int | Block, address: BaseAddress) -> None:
        self.txid = txid
        self.vout = vout
        self.amount = amount
        self.block = block
        self.address = address

    def __repr__(self) -> str:
        return pprint_class(
            self,
            [self.txid.hex(), self.vout, self.amount],
            {'block': self.block, 'address': self.address}
        )

    @overload
    def as_dict(self, *, hexadecimal: Literal[True] = True) -> UnspentDict[str]:
        ...
    @overload
    def as_dict(self, *, hexadecimal: Literal[False]) -> UnspentDict[bytes]:
        ...
    def as_dict(self, *, hexadecimal: bool = True) -> UnspentDict:
        pkscript = self.address.pkscript.serialize()
        return {
            'txid': self.txid.hex() if hexadecimal else self.txid,
            'vout': self.vout,
            'amount': self.amount,
            'block': self.block,
            'pkscript': pkscript.hex() if hexadecimal else pkscript,
            'address': self.address.string
        }


class RawInput(SupportsCopy, SupportsDump, SupportsSerialize):
    """An input that doesn't have info about amount"""

    vout: TypeConverter[int, uint32] = TypeConverter(uint32)
    sequence: TypeConverter[int, uint32] = TypeConverter(uint32)

    def __init__(self, txid: bytes, vout: int, sequence: int = DEFAULT_SEQUENCE,
                 script: Optional[Script] = None, witness: Optional[Script] = None) -> None:
        """
        :param txid: Transaction hex.
        :param vout: Unspent output index in transaction.
        :param sequence: Sequence (more in Bitcoin docs).
        """
        self.txid = txid
        self.vout = vout
        self.sequence = sequence

        self.script = script or Script()
        self.witness = witness or Script()

    def __repr__(self) -> str:
        return f'{self.txid.hex()}:{self.vout}'

    @classmethod
    def from_unspent(cls, unspent: Unspent, sequence: int = DEFAULT_SEQUENCE) -> 'RawInput':
        return cls(unspent.txid, unspent.vout, sequence)

    def custom_sign(self, script: Optional[Script], witness: Optional[Script]) -> None:
        for n, v in {
            'script': script,
            'witness': witness
        }.items():
            if v:
                setattr(self, n, v)

    def clear(self):
        """Clear the script and the witness signatures"""
        self.script = Script()
        self.witness = Script()

    def copy(self) -> 'RawInput':
        return RawInput(self.txid, self.vout, self.sequence, self.script, self.witness)

    def serialize(self, *, exclude_script: bool = False, exclude_sequence: bool = False) -> bytes:
        b = b''.join([
            self.txid[::-1],
            self.vout.pack()
        ])

        if not exclude_script:
            sig = self.script.serialize()
            sig_size = varint(len(sig)).pack()
            b += sig_size + sig
        if not exclude_sequence:
            b += self.sequence.pack()

        return b

    @overload
    def as_dict(self, *, hexadecimal: Literal[True] = True) -> InputDict[str]:
        ...
    @overload
    def as_dict(self, *, hexadecimal: Literal[False]) -> InputDict[bytes]:
        ...
    def as_dict(self, *, hexadecimal: bool = True) -> InputDict:
        script = self.script.serialize()
        d: InputDict = {
            'txid': self.txid.hex() if hexadecimal else self.txid,
            'vout': self.vout,
            'script': script.hex() if hexadecimal else script
        }  # type: ignore
        if self.witness:
            witness = self.witness.serialize()
            d['witness'] = witness.hex() if hexadecimal else witness
        d['sequence'] = self.sequence
        return d


class UnsignableInput(RawInput, SupportsCopyAndAmount):
    """
    An input that has info about the amount, but doesn't have PrivateKey,
    which is why it can't be signed using .default_sign (but can still using .custom_sign)
    """

    amount: TypeConverter[int, int64] = TypeConverter(int64)

    def __init__(self, txid: bytes, vout: int, amount: int, sequence: int = DEFAULT_SEQUENCE,
                 script: Optional[Script] = None, witness: Optional[Script] = None) -> None:
        """
        :param amount: Input amount
        """
        super().__init__(txid, vout, sequence, script, witness)
        self.amount = amount

    def __repr__(self) -> str:
        d = cast(dict[str, str], self.as_dict())
        for k in ['script', 'witness']:
            d.pop(k, None)
        return pprint_class(self, kwargs=d)

    @classmethod
    def from_unspent(cls, unspent: Unspent, sequence: int = DEFAULT_SEQUENCE) -> 'UnsignableInput':
        return cls(unspent.txid, unspent.vout, unspent.amount, sequence)

    def copy(self) -> 'UnsignableInput':
        return UnsignableInput(self.txid, self.vout, self.amount, self.sequence, self.script, self.witness)

    @overload
    def as_dict(self, *, hexadecimal: Literal[True] = True) -> InputDict[str]:
        ...
    @overload
    def as_dict(self, *, hexadecimal: Literal[False]) -> InputDict[bytes]:
        ...
    def as_dict(self, *, hexadecimal: bool = True) -> InputDict:
        d = OrderedDict(super().as_dict(hexadecimal=hexadecimal))  # type: ignore
        d['amount'] = self.amount
        for K in ['amount', 'vout', 'txid']:
            d.move_to_end(K, last=False)
        return dict(d)  # type: ignore


class CoinbaseInput(UnsignableInput):
    DEFAULT_TXID = b'\x00' * 32
    DEFAULT_VOUT = 4294967295
    DEFAULT_SEQUENCE = 4294967295
    DEFAULT_WITNESS = Script(b'\x00' * 32)  # default witness for coinbase transactions after segwit (bip141)

    def __init__(self, script: Script | bytes, witness: Script | bytes) -> None:
        """
        :param script: Deserialized Script() or serialized bytes
        :param witness: Deserialized Script() or serialized bytes
        """
        super().__init__(self.DEFAULT_TXID, self.DEFAULT_VOUT, 0, self.DEFAULT_SEQUENCE)
        self.script = script if isinstance(script, Script) else Script.deserialize(script, freeze=True)
        self.witness = witness if isinstance(witness, Script) else Script.deserialize(witness, segwit=True, freeze=True)

    def __repr__(self) -> str:
        return pprint_class(self, kwargs={
            'script': self.script.serialize().hex()
        })

    def parse_height(self) -> int:
        """
        Try to parse height in coinbase script, it's possible for blocks with version 2 and more (bip-0034).
        For blocks with ver < 2 returns wrong value.
        """
        return bytes2int(self.script[0], 'little')  # type: ignore todo: maybe prevent indexerror?

    @overload
    def as_dict(self, *, hexadecimal: Literal[True] = True) -> InputDict[str]:
        ...
    @overload
    def as_dict(self, *, hexadecimal: Literal[False]) -> InputDict[bytes]:
        ...
    def as_dict(self, *, hexadecimal: bool = True) -> InputDict:
        return RawInput.as_dict(self, hexadecimal=hexadecimal)  # type: ignore


class Input(UnsignableInput):
    """A full filled input that has both amount and PrivateKey (can be signed with .default_sign)"""

    def __init__(self, txid: bytes, vout: int, amount: int, private: PrivateKey,
                 address: BaseAddress, sequence: int = DEFAULT_SEQUENCE,
                 script: Optional[Script] = None, witness: Optional[Script] = None) -> None:
        """
        :param key: PrivateKey of the address below.
        :param address: Address that the Input belongs to.
        """
        super().__init__(txid, vout, amount, sequence, script, witness)
        self.private = private
        self.address = address

    @classmethod
    def from_unspent(cls,
                     unspent: Unspent,
                     private: PrivateKey,
                     address: BaseAddress,
                     sequence: int = DEFAULT_SEQUENCE) -> 'Input':
        return cls(unspent.txid, unspent.vout, unspent.amount, private, address, sequence)

    def default_sign(self, tx: 'Transaction') -> None:  # default sign
        """
        Default sign supports P2PKH, P2SH-P2WPKH, P2WPKH, P2WSH.
        The last three use a witness (tx.get_hash4sign(segwit=True)).
        """
        try:
            index = tx.inputs.index(self)
        except ValueError:
            raise ValueError(f'received tx has no input {repr(self)}') from None

        if isinstance(self.address, P2WSH):
            witness = Script(opcode.OP_1, self.private.public.to_bytes().hex(), opcode.OP_1, opcode.OP_CHECKMULTISIG)
            hash4sign = tx.get_hash4sign(index, witness, segwit=True)
            sig = self.private.sign_tx(hash4sign)
            self.witness = Script(b'', sig, witness.serialize().hex())
            return

        pb_ophash160 = op_hash160(self.private.public.to_bytes())
        script4hash = Script(opcode.OP_DUP, opcode.OP_HASH160, pb_ophash160, opcode.OP_EQUALVERIFY, opcode.OP_CHECKSIG)
        hash4sign = tx.get_hash4sign(index, script4hash, segwit=not isinstance(self.address, P2PKH))
        sig = Script(self.private.sign_tx(hash4sign), self.private.public.to_bytes().hex())

        match self.address:
            case P2PKH():
                self.script = sig

            case P2SH():
                if self.private.public.change_network(self.address.network).get_address(AddressType.P2SH_P2WPKH) != self.address:
                    raise TypeError('from P2SH addresses default_sign supports P2SH-P2WPKH input only, but other type received')

                self.script = Script(Script(opcode.OP_0, pb_ophash160).serialize().hex())
                self.witness = sig

            case P2WPKH():
                self.witness = sig

            case _:
                raise TypeError('supports only P2PKH, P2SH, P2WPKH, P2WSH')

    def copy(self) -> 'Input':
        return Input(self.txid, self.vout, self.amount, self.private, self.address, self.sequence, self.script, self.witness)

    @overload
    def as_dict(self, *, hexadecimal: Literal[True] = True) -> InputDict[str]:
        ...
    @overload
    def as_dict(self, *, hexadecimal: Literal[False]) -> InputDict[bytes]:
        ...
    def as_dict(self, *, hexadecimal: bool = True) -> InputDict:
        d = super().as_dict(hexadecimal=hexadecimal)  # type: ignore
        sequence = d.pop('sequence')
        d['address'] = self.address.string
        d['sequence'] = sequence  # type: ignore
        return d


class Output(SupportsCopyAndAmount, SupportsDump, SupportsSerialize):
    amount: TypeConverter[int, int64] = TypeConverter(int64)

    def __init__(self, pkscript: Script, amount: int) -> None:
        self.pkscript = pkscript
        self.amount = amount
        try:
            self.address: BaseAddress | None = from_pkscript(pkscript)
        except:
            self.address = None

    @classmethod
    def from_address(cls, address: BaseAddress, amount: int) -> Self:
        return cls(address.pkscript, amount)

    def __repr__(self):
        return pprint_class(self, kwargs={
            'pkscript': self.pkscript,
            'amount': self.amount,
            'address': self.address
        })

    def copy(self) -> 'Output':
        return Output(self.pkscript, self.amount)

    def serialize(self) -> bytes:
        b = self.pkscript.serialize()
        size = varint(len(b)).pack()
        return b''.join([self.amount.pack(), size, b])

    @overload
    def as_dict(self, *, hexadecimal: Literal[True] = True) -> OutputDict[str]:
        ...
    @overload
    def as_dict(self, *, hexadecimal: Literal[False]) -> OutputDict[bytes]:
        ...
    def as_dict(self, *, hexadecimal: bool = True) -> OutputDict:
        pkscript = self.pkscript.serialize()
        d: OutputDict = {
            'pkscript': pkscript.hex() if hexadecimal else pkscript,
            'amount': self.amount,
        }
        if self.address:
            d['address'] = self.address.string
        return d


class EmptyOutput(Output):
    def __init__(self):
        super().__init__(Script(), NEGATIVE_SATOSHI)


class _Hash4SignGenerator:
    _SAME_OUT_INDEX_ERROR = lambda i: LookupError(
        f'SIGHASH_SINGLE signs the output with the same index as the input, '
        f'the input index is {i}, output with that index don\'t exists'
    )

    @classmethod
    def get_default(cls, tx: 'RawTransaction', inp_index: int, script4hash: Script, sighash: int = SIGHASHES['all']) -> bytes:
        tx, sighash = tx.copy(), uint32(sighash)
        tx.clear_inputs()
        tx.inputs[inp_index].script = script4hash

        if (sighash & 0x1f) == SIGHASHES['none']:
            tx.outputs.clear()

            for n, _ in enumerate(tx.inputs):
                if n != inp_index:
                    tx.inputs[n].sequence = EMPTY_SEQUENCE

        elif (sighash & 0x1f) == SIGHASHES['single']:
            try:
                out = tx.outputs[inp_index]
            except IndexError:
                raise cls._SAME_OUT_INDEX_ERROR(inp_index) from None

            tx.outputs = ioList(EmptyOutput() for _ in range(inp_index)) + [out,]

            for n, inp in enumerate(tx.inputs):
                if n != inp_index:
                    inp.sequence = EMPTY_SEQUENCE

        if sighash & SIGHASHES['anyonecanpay']:
            tx.inputs = [tx.inputs[inp_index]]

        serialized = tx.serialize(exclude_witnesses=True) + sighash.pack()
        return d_sha256(serialized)

    @classmethod
    def get_segwit(cls, tx: 'Transaction', inp_index: int, script4hash: Script, sighash: int = SIGHASHES['all']) -> bytes:
        tx, sighash = tx.copy(), uint32(sighash)
        inps = seq = outs = b'\x00' * 32
        base = sighash & 0x1f
        sign_all = base not in [SIGHASHES['single'], SIGHASHES['none']]

        if not sighash & 0xf0 == SIGHASHES['anyonecanpay']:
            inps = b''.join(inp.serialize(exclude_script=True, exclude_sequence=True) for inp in tx.inputs)

            if sign_all:
                seq = b''.join(inp.sequence.pack() for inp in tx.inputs)

        if sign_all:
            outs = b''.join(out.serialize() for out in tx.outputs)

        elif base == SIGHASHES['single']:
            try:
                out = tx.outputs[inp_index]
            except IndexError:
                raise cls._SAME_OUT_INDEX_ERROR(inp_index) from None

            outs = out.serialize()

        # if tx.inputs[inp_index].amount is None:
        #      raise TypeError('Transaction.get_hash4sign(input_index, ..., segwit=True) '
        #                      'requires Input.amount is not None')

        s4h_b = script4hash.serialize()
        s4h_size = varint(len(s4h_b)).pack()

        return d_sha256(b''.join([
            tx.version.pack(),
            d_sha256(inps),
            d_sha256(seq),
            tx.inputs[inp_index].serialize(exclude_script=True, exclude_sequence=True),
            s4h_size,
            s4h_b,
            tx.inputs[inp_index].amount.pack(),
            tx.inputs[inp_index].sequence.pack(),
            d_sha256(outs),
            tx.locktime.pack(),
            sighash.pack()
        ]))


class TransactionDeserializer:
    def __init__(self, rawbytes: bytes) -> None:
        self.b = rawbytes
        # start, end
        self.s = 0
        self.e = len(rawbytes)

    def is_segwit(self) -> bool:
        return self.b[4] == 0

    def seek(self, s: int = 0, e: Optional[int] = None) -> None:
        self.s = s
        self.e = len(self.b) if e is None else e

    def read(self) -> bytes:
        return self.b[self.s:self.e]

    def pop(self, size: int) -> bytes:
        if size < 0:
            e = self.e
            self.e += size
            if self.e < self.s:
                self.e = self.s
            return self.b[self.e:e]

        else:
            s = self.s
            self.s += size
            if self.s > self.e:
                self.s = self.e
            return self.b[s:self.s]

    def pop_size(self, segwit: bool = False) -> int:
        size, b = varint.unpack(self.read(), increased_separator=segwit)
        self.s += len(size.pack())
        return size

    @overload
    def deserialize(self, *, hexadecimal: Literal[True] = True) -> TransactionDict[str]:
        ...
    @overload
    def deserialize(self, *, hexadecimal: Literal[False]) -> TransactionDict[bytes]:
        ...
    def deserialize(self, *, hexadecimal: bool = True) -> TransactionDict:
        """
        :param hexdecimal: Return hex string
        """
        segwit = self.is_segwit()
        tx: TransactionDict = {
            'inputs': [],
            'outputs': [],
            'version': uint32.unpack(self.pop(4)),
            'locktime': uint32.unpack(self.pop(-4))
        }

        if segwit:
            self.pop(2)  # pop marker and flag

        # inputs
        inps_count = self.pop_size()
        for _ in range(inps_count):
            tx['inputs'].append({
                'txid': self.pop(32)[::-1].hex() if hexadecimal else self.pop(32)[::-1],
                'vout': uint32.unpack(self.pop(4)),
                'script': self.pop(self.pop_size()).hex() if hexadecimal else self.pop(self.pop_size()),
                'sequence': uint32.unpack(self.pop(4))
            })

        # outputs
        outs_count = self.pop_size()
        for _ in range(outs_count):
            amount = int64.unpack(self.pop(8))
            tx['outputs'].append({
                'pkscript': self.pop(self.pop_size()).hex() if hexadecimal else self.pop(self.pop_size()),
                'amount': amount
            })

        # witnesses
        if segwit:
            for inp_index in range(inps_count):
                items_count = self.pop_size(segwit=True)
                witness = Script.deserialize(self.read(), segwit=True, length=items_count).serialize(segwit=True)
                tx['inputs'][inp_index]['witness'] = witness.hex() if hexadecimal else witness

                # sort order
                seq = tx['inputs'][inp_index].pop('sequence')  # type: ignore
                tx['inputs'][inp_index]['sequence'] = seq  # type: ignore

                self.pop(len(witness))

        self.seek()
        return tx


class RawTransaction(SupportsDump, SupportsSerialize, SupportsCopy):
    inputs: TypeConverter[Iterable[RawInput], list[RawInput]] = TypeConverter(list)
    outputs: TypeConverter[Iterable[Output], ioList[Output]] = TypeConverter(ioList)
    version: TypeConverter[int, uint32] = TypeConverter(uint32)
    locktime: TypeConverter[int, uint32] = TypeConverter(uint32)

    def __init__(self, inputs: Iterable[RawInput], outputs: Iterable[Output],
                 version: int = DEFAULT_VERSION, locktime: int = DEFAULT_LOCKTIME) -> None:
        self.inputs = list(inputs)
        self.outputs = ioList(outputs)
        self.version = version
        self.locktime = locktime

    def __repr__(self):
        return str(self.as_dict())

    def __eq__(self, value: object) -> bool:
        match value:
            case RawTransaction():
                return type(self) is type(value) and self.as_dict() == value.as_dict()
            case _:
                return super().__eq__(value)

    @property
    def id(self) -> bytes:
        return d_sha256(self.serialize(exclude_witnesses=True))[::-1]

    @property
    def weight(self) -> int:
        w = len(self.serialize(exclude_witnesses=True)) * 4
        return sum([
            w,
            2,  # segwit flag+mark size
            len(b''.join(varint(len(inp.witness)).pack() +
                         inp.witness.serialize(segwit=True) for inp in self.inputs))
        ]) if self.is_segwit() else w

    @property
    def vsize(self) -> int:
        vsize = self.weight // 4
        return vsize + 1 if self.weight % 4 else vsize

    @property
    def size(self) -> int:
        return len(self.serialize())

    @classmethod
    def deserialize(cls, raw: bytes) -> 'RawTransaction':
        d: TransactionDict[bytes] = TransactionDeserializer(raw).deserialize(hexadecimal=False)

        # convert dict inputs to Input objects
        inputs = []
        for inp_dict in d['inputs']:
            script, witness = inp_dict['script'], inp_dict.get('witness', b'')
            if inp_dict['txid'] == b'\x00' * 32:
                inp_instance = CoinbaseInput(script, witness)

            else:
                inp_instance = RawInput(
                    inp_dict['txid'],
                    inp_dict['vout'],
                    sequence=inp_dict['sequence'],
                    script=Script.deserialize(script),
                    witness=Script.deserialize(witness, segwit=True)
                )

            inputs.append(inp_instance)

        # convert dict outputs to Output objects
        outputs = []
        for out_dict in d['outputs']:
            outputs.append(Output(Script.deserialize(out_dict['pkscript']), out_dict['amount']))

        return RawTransaction(inputs, outputs, d['version'], d['locktime'])

    def is_coinbase(self) -> bool:
        return any(isinstance(i, CoinbaseInput) for i in self.inputs)

    def is_segwit(self) -> bool:
        return any([inp.witness for inp in self.inputs])

    def get_hash4sign(self, input_index: int, script4hash: Script, *, sighash: int = SIGHASHES['all']) -> bytes:
        """
        Get hash for sign. Doesn't support segwit (cause no RawInput.amount), use Transaction instead
        :param input_index:
        :param script4hash: Script which will be used in default input script field.
        :param sighash: Signature Hash (more in Bitcoin Core documentation).
        :return: Hash for private key signing.
        """
        return _Hash4SignGenerator.get_default(self, input_index, script4hash, sighash)

    def clear_inputs(self) -> None:
        """Apply Input.clear() to all inputs"""
        for inp in self.inputs:
            inp.clear()

    def serialize(self, *, exclude_witnesses: bool = False) -> bytes:
        segwit = not exclude_witnesses and self.is_segwit()
        return b''.join([
            self.version.pack(),
            b'\x00\x01' if segwit else b'',  # segwit mark + flag
            varint(len(self.inputs)).pack(),
            b''.join(inp.serialize() for inp in self.inputs),
            varint(len(self.outputs)).pack(),
            b''.join(out.serialize() for out in self.outputs),
            b''.join(varint(len(inp.witness)).pack() + inp.witness.serialize(segwit=True) for inp in self.inputs) if segwit else b'',
            self.locktime.pack()
        ])

    def copy(self) -> Self:
        return type(self)(
            [inp.copy() for inp in self.inputs],
            [out.copy() for out in self.outputs],
            self.version,
            self.locktime
        )

    @overload
    def as_dict(self, *, hexadecimal: Literal[True] = True) -> TransactionDict[str]:
        ...
    @overload
    def as_dict(self, *, hexadecimal: Literal[False]) -> TransactionDict[bytes]:
        ...
    def as_dict(self, *, hexadecimal: bool = True) -> TransactionDict:
        return {
            'inputs': [inp.as_dict(hexadecimal=hexadecimal) for inp in self.inputs],  # type: ignore
            'outputs': [out.as_dict(hexadecimal=hexadecimal) for out in self.outputs],  # type: ignore
            'version': self.version,
            'locktime': self.locktime
        }


class Transaction(RawTransaction):
    inputs: TypeConverter[Iterable[UnsignableInput], ioList[UnsignableInput]] = TypeConverter(ioList)

    def __init__(self, inputs: Iterable[UnsignableInput], outputs: Iterable[Output],
                 version: int = DEFAULT_VERSION, locktime: int = DEFAULT_LOCKTIME) -> None:
        super().__init__(inputs, outputs, version, locktime)
        self.inputs = ioList(inputs)

    @property
    def fee(self) -> int:
        return self.inputs.amount - self.outputs.amount if not self.is_coinbase() else 0

    @classmethod
    def fromraw(cls, r: RawTransaction, amounts: list[int]) -> 'Transaction':  # todo: add keys arg maybe
        """
        :param amounts: Amounts for each input
        """
        assert len(r.inputs) == len(amounts), 'inputs and amounts length must be same'
        return cls(
            ioList(
                UnsignableInput(
                    i.txid,
                    i.vout,
                    a,
                    i.sequence,
                    i.script,
                    i.witness
                ) if not isinstance(i, CoinbaseInput) else i.copy()
                for i, a in zip(r.inputs, amounts)
            ),
            r.outputs.copy(),
            r.version,
            r.locktime
        )

    @classmethod
    def deserialize(cls, raw: bytes, amounts: list[int]) -> 'Transaction':
        """
        :param amounts: Amounts for each input
        """
        return cls.fromraw(RawTransaction.deserialize(raw), amounts)

    def get_hash4sign(self, input_index: int, script4hash: Script, *, segwit: bool, sighash: int = SIGHASHES['all']) -> bytes:
        """
        Get hash for sign (support segwit)
        :param input_index:
        :param script4hash: Script which will be used in default input script field.
        :param segwit: If hash4sign needed for script in witness - use segwit=True.
                       Else if using default input script - False.
        :param sighash: Signature Hash (more in Bitcoin Core documentation).
        :return: Hash for private key signing.
        """
        getter = _Hash4SignGenerator.get_segwit if segwit else _Hash4SignGenerator.get_default
        return getter(self, input_index, script4hash, sighash)

    def default_sign(self, *, pass_unsignable: bool = False) -> None:  # todo: rename to .sign()
        """
        :param pass_unsignable: Pass inputs that don't support .default_sign() otherwise raise AssertionError
        """
        for inp in self.inputs:
            try:
                assert isinstance(inp, Input), f'supports only Input (not {type(inp).__name__})'
            except AssertionError as e:
                if not pass_unsignable:
                    raise e from None
                continue

            inp.default_sign(self)


class BroadcastedTransaction(Transaction):
    block: TypeConverter[int, Block] = TypeConverter(Block)

    def __init__(self,
                 inputs: Iterable[UnsignableInput],
                 outputs: Iterable[Output],
                 block: int | Block,
                 network: NetworkType = DEFAULT_NETWORK,
                 version: int = DEFAULT_VERSION,
                 locktime: int = DEFAULT_LOCKTIME) -> None:
        super().__init__(inputs, outputs, version, locktime)
        self.block = Block(block)
        self.network = network

    @classmethod
    def fromraw(cls,
                r: RawTransaction | Transaction,
                block: int | Block,
                network: NetworkType = DEFAULT_NETWORK,
                amounts: Optional[list[int]] = None) -> 'BroadcastedTransaction':
        """Convert RawTransaction/Transaction to BroadcastedTransaction"""
        if type(r) is RawTransaction:
            assert amounts and len(r.inputs) == len(amounts), 'for RawTransaction amounts should be specified'
            ins = ioList(
                UnsignableInput(
                    i.txid,
                    i.vout,
                    a,
                    i.sequence,
                    i.script,
                    i.witness
                ) if not isinstance(i, CoinbaseInput) else i.copy()
                for i, a in zip(r.inputs, amounts)
            )
        else:
            ins: ioList[UnsignableInput] = r.inputs.copy()  # type: ignore

        return cls(ins, r.outputs.copy(), block, network, r.version, r.locktime)

    @classmethod
    def deserialize(cls, raw: bytes, amounts: list[int], block: int | Block, network: NetworkType = DEFAULT_NETWORK) -> 'BroadcastedTransaction':
        return cls.fromraw(RawTransaction.deserialize(raw), block, network, amounts)

    def get_confirmations(self, head: Block) -> int:
        return 0 if self.block < 0 else int(head - self.block)
