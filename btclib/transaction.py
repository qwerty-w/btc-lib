from abc import abstractmethod
from collections import OrderedDict
from typing import Any, Iterable, Literal, Mapping, Optional, Protocol, Self, TypedDict, \
    NotRequired, cast, overload, runtime_checkable
import json

from btclib import exceptions
from btclib.services import NetworkAPI, Unspent
from btclib.script import Script
from btclib.utils import d_sha256, uint32, sint64, dint, pprint_class, TypeConverter
from btclib.address import Address, PrivateKey, P2PKH, P2SH, P2WPKH, P2WSH, from_script_pub_key
from btclib.const import DEFAULT_NETWORK, DEFAULT_SEQUENCE, DEFAULT_VERSION, DEFAULT_LOCKTIME, \
    SIGHASHES, EMPTY_SEQUENCE, NEGATIVE_SATOSHI, AddressType, NetworkType


@runtime_checkable
class SupportsCopy(Protocol):
    @abstractmethod
    def copy(self) -> 'SupportsCopy':
        ...


@runtime_checkable
class SupportsDump(Protocol):
    @abstractmethod
    def as_dict(self) -> dict:
        ...

    @abstractmethod
    def as_json(self, value: Mapping[Any, Any] | list, indent: Optional[int] = None) -> str:
        return json.dumps(value, indent=indent)


@runtime_checkable
class SupportsSerialize(Protocol):
    @abstractmethod
    def serialize(self) -> str | bytes:
        ...


@runtime_checkable
class SupportsAmount(Protocol):
    amount: int = NotImplemented


class InputDict(TypedDict):
    txid: str
    vout: uint32
    script: str
    witness: NotRequired[str]
    sequence: uint32


class OutputDict(TypedDict):
    script_pub_key: str
    amount: sint64


class TransactionDict(TypedDict):
    inputs: list[InputDict]
    outputs: list[OutputDict]
    version: uint32
    locktime: uint32


class RawInput(SupportsCopy, SupportsDump, SupportsSerialize):
    """An input that doesn't have info about amount"""

    vout: TypeConverter[int, uint32] = TypeConverter(uint32)
    sequence: TypeConverter[int, uint32] = TypeConverter(uint32)

    def __init__(self, txid: str, vout: int, sequence: int = DEFAULT_SEQUENCE):
        """
        :param txid: Transaction hex.
        :param vout: Unspent output index in transaction.
        :param sequence: Sequence (more in Bitcoin docs).
        """
        self.txid = txid
        self.vout = vout
        self.sequence = sequence

        self.script = Script()
        self.witness = Script()

    def __repr__(self) -> str:
        return f'{self.txid}:{self.vout}'

    @classmethod
    def from_unspent(cls, unspent: Unspent, sequence: int = DEFAULT_SEQUENCE) -> 'RawInput':
        return cls(unspent.txid, unspent.vout, sequence)

    def custom_sign(self, script: Optional[str | Script], witness: Optional[str | Script]) -> None:
        for n, v in {
            'script': script,
            'witness': witness
        }.items():
            if v:
                setattr(self, n, Script.deserialize(v) if isinstance(v, str) else v)

    def clear(self):
        """Clear the script and the witness signatures"""
        self.script = Script()
        self.witness = Script()

    def _copy(self, ins: Self) -> Self:
        ins.script = self.script
        ins.witness = self.witness
        return ins

    def copy(self) -> 'RawInput':
        return self._copy(self.__class__(self.txid, self.vout, self.sequence))

    def serialize(self, *, exclude_script: bool = False, exclude_sequence: bool = False) -> bytes:
        b = b''.join([
            bytes.fromhex(self.txid)[::-1],
            self.vout.pack()
        ])

        if not exclude_script:
            sig = self.script.serialize()
            sig_size = dint(len(sig)).pack()
            b += sig_size + sig
        if not exclude_sequence:
            b += self.sequence.pack()

        return b

    def as_dict(self) -> InputDict:
        d: InputDict = {
            'txid': self.txid,
            'vout': self.vout,
            'script': self.script.serialize().hex()
        }  # type: ignore
        if not self.witness.is_empty():
            d['witness'] = self.witness.serialize().hex()
        d['sequence'] = self.sequence
        return d

    def as_json(self, *, indent: Optional[int] = None) -> str:
        return super().as_json(self.as_dict(), indent=indent)


class UnsignableInput(RawInput, SupportsAmount):
    """
    An input that has info about the amount, but doesn't have PrivateKey, 
    which is why it can't be signed using .default_sign (but can still using .custom_sign)
    """

    amount: TypeConverter[int, sint64] = TypeConverter(sint64)

    def __init__(self, txid: str, vout: int, amount: int, sequence: int = DEFAULT_SEQUENCE):
        """
        :param amount: Input amount
        """
        super().__init__(txid, vout, sequence)
        self.amount = amount

    def __repr__(self) -> str:
        return pprint_class(self, kwargs=self.as_dict())

    @classmethod
    def from_unspent(cls, unspent: Unspent, sequence: int = DEFAULT_SEQUENCE) -> RawInput:
        return cls(unspent.txid, unspent.vout, unspent.amount, sequence)

    def copy(self) -> 'UnsignableInput':
        return self._copy(self.__class__(self.txid, self.vout, self.amount, self.sequence))

    def as_dict(self) -> dict[str, str | uint32 | sint64]:
        d = cast(OrderedDict[str, str | uint32 | sint64], OrderedDict(super().as_dict()))
        d['amount'] = self.amount
        for K in ['amount', 'vout', 'txid']:
            d.move_to_end(K, last=False)
        return dict(d)


class Input(UnsignableInput):
    """A full filled input that has both amount and PrivateKey (can be signed with .default_sign)"""

    def __init__(self, txid: str, vout: int, amount: int, private: PrivateKey, address: Address, sequence: int = DEFAULT_SEQUENCE):
        """
        :param key: PrivateKey of the address below.
        :param address: Address that the Input belongs to.
        """
        super().__init__(txid, vout, amount, sequence)
        self.private = private
        self.address = address

    @classmethod
    def from_unspent(cls, unspent: Unspent, private: PrivateKey, address: Address, sequence: int = DEFAULT_SEQUENCE) -> 'Input':
        return cls(unspent.txid, unspent.vout, unspent.amount, private, address, sequence)

    def default_sign(self, tx: 'Transaction') -> None:  # default sign
        """
        Default sign supports P2PKH, P2SH-P2WPKH, P2WPKH, P2WSH.
        The last three use a witness (tx.get_hash4sign(segwit=True))
        """
        try:
            index = tx.inputs.index(self)
        except ValueError:
            raise ValueError(f'received tx has no input {repr(self)}') from None

        if isinstance(self.address, P2WSH):
            witness = Script('OP_1', self.private.public.to_bytes().hex(), 'OP_1', 'OP_CHECKMULTISIG')
            hash4sign = tx.get_hash4sign(index, witness, segwit=True)
            sig = self.private.sign_tx(hash4sign)
            self.witness = Script('OP_0', sig, witness.serialize().hex())
            return

        script4hash = Script('OP_DUP', 'OP_HASH160', self.private.public.get_hash160(), 'OP_EQUALVERIFY', 'OP_CHECKSIG')
        hash4sign = tx.get_hash4sign(index, script4hash, segwit=not isinstance(self.address, P2PKH))
        sig = Script(self.private.sign_tx(hash4sign), self.private.public.to_bytes().hex())

        match self.address:
            case P2PKH():
                self.script = sig

            case P2SH():
                if self.private.public.get_address(AddressType.P2SH_P2WPKH, self.address.network).string != self.address.string:
                    raise exceptions.DefaultSignSupportOnlyP2shP2wpkh

                self.script = Script(Script('OP_0', self.private.public.get_hash160()).serialize().hex())
                self.witness = sig

            case P2WPKH():
                self.witness = sig

            case _:
                raise exceptions.InvalidAddressInstanceType(type(self.address))
    
    def copy(self) -> 'Input':
        return self._copy(self.__class__(self.txid, self.vout, self.amount, self.private, self.address, self.sequence))

    def as_dict(self) -> dict:
        d = super().as_dict()
        d['address'] = self.address.string
        return d


class Output(SupportsAmount, SupportsDump, SupportsSerialize, SupportsCopy):
    amount: TypeConverter[int, sint64] = TypeConverter(sint64)

    def __init__(self, script_pub_key: str | Script, amount: int):
        """
        NOTICE: Do not forget that on the bitcoin network, coins are transferred by
        scriptPubKey, not by the string (base58/bech32) representation of the address.
        This means that if the inputs are on the mainnet network, and as an output you
        use Output(Address("<testnet network address>")), then coins will be transferred
        to <mainnet network address>, because they have the same scriptPubKey.
        """
        self.script_pub_key: Script = script_pub_key if isinstance(script_pub_key, Script) else Script.deserialize(script_pub_key)
        self.amount = amount
        try:
            self._address = from_script_pub_key(script_pub_key)
        except:
            self._address = None

    @classmethod
    def from_address(cls, address: Address, amount: int) -> 'Output':
        return cls(address.script_pub_key, amount)

    def __repr__(self):
        return pprint_class(self, kwargs={
            'script_pub_key': self.script_pub_key,
            'amount': self.amount
        } | ({ 'address': self._address } if self._address else {}))

    def copy(self) -> 'Output':
        return Output(self.script_pub_key, self.amount)

    def serialize(self) -> bytes:
        b = self.script_pub_key.serialize()
        size = dint(len(b)).pack()
        return b''.join([self.amount.pack(), size, b])

    def as_dict(self) -> OutputDict:
        return {
            'script_pub_key': self.script_pub_key.serialize().hex(),
            'amount': self.amount
        }

    def as_json(self, *, indent: Optional[int] = None, **kwargs) -> str:
        return super().as_json(self.as_dict(**kwargs), indent=indent)


class EmptyOutput(Output):
    def __init__(self):
        super().__init__(Script(), NEGATIVE_SATOSHI)


class _Hash4SignGenerator:
    @staticmethod
    def get_default(tx: 'RawTransaction', inp_index: int, script4hash: Script, sighash: int = SIGHASHES['all']) -> bytes:
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
                raise exceptions.SighashSingleRequiresInputAndOutputWithSameIndexes(inp_index) from None

            tx.outputs = ioList(EmptyOutput() for _ in range(inp_index)) + [out,]

            for n, inp in enumerate(tx.inputs):
                if n != inp_index:
                    inp.sequence = EMPTY_SEQUENCE

        if sighash & SIGHASHES['anyonecanpay']:
            tx.inputs = [tx.inputs[inp_index]]

        serialized = tx.serialize(exclude_witnesses=True) + sighash.pack()
        return d_sha256(serialized)

    @staticmethod
    def get_segwit(tx: 'Transaction', inp_index: int, script4hash: Script, sighash: int = SIGHASHES['all']) -> bytes:
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
                raise exceptions.SighashSingleRequiresInputAndOutputWithSameIndexes(inp_index) from None

            outs = out.serialize()

        # if tx.inputs[inp_index].amount is None:
        #     raise exceptions.SegwitHash4SignRequiresInputAmount

        s4h_b = script4hash.serialize()
        s4h_size = dint(len(s4h_b)).pack()

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
    def __init__(self, raw: bytes):
        self.hex = raw.hex()
        self.raw = raw

    def is_segwit_tx(self) -> bool:
        return self.raw[4] == 0

    def pop(self, value: int) -> bytes:
        if value >= 0:
            data = self.raw[:value]
            self.raw = self.raw[value:]

        else:
            data = self.raw[value:]
            self.raw = self.raw[:value]

        return data

    def pop_size(self) -> int:
        size, self.raw = dint.unpack(self.raw)
        return size

    def deserialize(self) -> TransactionDict:
        segwit = self.is_segwit_tx()
        data: TransactionDict = {
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
            data['inputs'].append({
                'txid': self.pop(32)[::-1].hex(),
                'vout': uint32.unpack(self.pop(4)),
                'script': Script.deserialize(self.pop(self.pop_size())).serialize().hex(),
                'sequence': uint32.unpack(self.pop(4))
            })

        # outputs
        outs_count = self.pop_size()
        for _ in range(outs_count):
            amount = sint64.unpack(self.pop(8))
            data['outputs'].append({
                'script_pub_key': self.pop(self.pop_size()).hex(),
                'amount': amount
            })

        # witnesses
        if segwit:
            for inp_index in range(inps_count):
                items_count = self.pop_size()
                script = Script.deserialize(self.raw, segwit=True, max_items=items_count)
                data['inputs'][inp_index]['witness'] = script.serialize(segwit=True).hex()

                # sort order
                seq = data['inputs'][inp_index].pop('sequence')  # type: ignore
                data['inputs'][inp_index]['sequence'] = seq

                self.pop(len(script.serialize(segwit=True)))

        return data


class ioList[T: 'SupportsAmount'](list[T]):
    @property
    def amount(self) -> int:
        return sum(x.amount for x in self)


class RawTransaction(SupportsDump, SupportsSerialize, SupportsCopy):
    inputs: TypeConverter[Iterable[RawInput], list[RawInput]] = TypeConverter(list)
    outputs: TypeConverter[Iterable[Output], ioList[Output]] = TypeConverter(ioList)
    version: TypeConverter[int, uint32] = TypeConverter(uint32)
    locktime: TypeConverter[int, uint32] = TypeConverter(uint32)

    def __init__(self, inputs: Iterable[RawInput], outputs: Iterable[Output], version: int = DEFAULT_VERSION,
                 locktime: int = DEFAULT_LOCKTIME):
        self.inputs = list(inputs)
        self.outputs = ioList(outputs)
        self.version = version
        self.locktime = locktime

    def __repr__(self):
        return str(self.as_dict())
    
    @property
    def weight(self) -> int:
        w = len(self.serialize(exclude_witnesses=True)) * 4
        return sum([
            w,
            2,  # segwit mark size
            len(b''.join(dint(len(inp.witness)).pack() + 
                         inp.witness.serialize(segwit=True) for inp in self.inputs))
        ]) if self.has_segwit_input() else w

    @property
    def size(self) -> int:
        return len(self.serialize())

    @classmethod
    def deserialize(cls, raw: bytes) -> 'RawTransaction':
        d = TransactionDeserializer(raw).deserialize()

        # convert dict inputs to Input objects
        inputs = []
        for inp_dict in d['inputs']:
            inp_instance = RawInput(
                inp_dict['txid'],
                inp_dict['vout'],
                sequence=inp_dict['sequence']
            )
            inp_instance.custom_sign(
                Script.deserialize(inp_dict['script']),
                Script.deserialize(inp_dict.get('witness', ''), segwit=True)
            )

            inputs.append(inp_instance)

        # convert dict outputs to Output objects
        outputs = []
        for out_dict in d['outputs']:
            outputs.append(Output(out_dict['script_pub_key'], out_dict['amount']))

        return RawTransaction(inputs, outputs, d['version'], d['locktime'])

    def get_id(self) -> str:
        return d_sha256(self.serialize(exclude_witnesses=True))[::-1].hex()

    def get_hash4sign(self, input_index: int, script4hash: Script, *, sighash: int = SIGHASHES['all']) -> bytes:
        """
        Get hash for sign. Doesn't support segwit (cause no RawInput.amount), use Transaction instead
        :param input_index:
        :param script4hash: Script which will be used in default input script field.
        :param sighash: Signature Hash (more in Bitcoin Core documentation).
        :return: Hash for private key signing.
        """
        return _Hash4SignGenerator.get_default(self, input_index, script4hash, sighash)

    def has_segwit_input(self) -> bool:
        return any([not inp.witness.is_empty() for inp in self.inputs])

    def clear_inputs(self):
        """Apply Input.clear() to all inputs"""
        for inp in self.inputs:
            inp.clear()

    def push(self, network: str) -> bool:
        tx_hex = self.serialize()
        getattr(NetworkAPI, 'broadcast_tx' + ('_testnet' if network == 'testnet' else ''))(tx_hex)
        return True

    def serialize(self, *, exclude_witnesses: bool = False) -> bytes:
        has_segwit = False if exclude_witnesses else self.has_segwit_input()
        return b''.join([
            self.version.pack(),
            b'\x00\x01' if has_segwit else b'',  # segwit mark
            dint(len(self.inputs)).pack(),
            b''.join(inp.serialize() for inp in self.inputs),
            dint(len(self.outputs)).pack(),
            b''.join(out.serialize() for out in self.outputs),
            b''.join(dint(len(inp.witness)).pack() + inp.witness.serialize(segwit=True) for inp in self.inputs) if has_segwit else b'',
            self.locktime.pack()
        ])

    def copy(self) -> Self:
        return type(self)(
            [inp.copy() for inp in self.inputs],
            [out.copy() for out in self.outputs],
            self.version,
            self.locktime
        )

    def as_dict(self) -> TransactionDict:
        return {
            'inputs': [inp.as_dict() for inp in self.inputs],
            'outputs': [out.as_dict() for out in self.outputs],
            'version': self.version,
            'locktime': self.locktime
        }

    def as_json(self, *, indent: Optional[int] = None) -> str:
        return super().as_json(self.as_dict(), indent=indent)


class Transaction(RawTransaction):
    inputs: TypeConverter[Iterable[UnsignableInput], ioList[UnsignableInput]] = TypeConverter(ioList)

    def __init__(self, inputs: Iterable[UnsignableInput], outputs: Iterable[Output], version: int = DEFAULT_VERSION, locktime: int = DEFAULT_LOCKTIME):
        super().__init__(inputs, outputs, version, locktime)
        self.inputs = ioList(inputs)

    @property
    def fee(self) -> int:
        return self.inputs.amount - self.outputs.amount

    @classmethod
    def from_raw_transaction(cls, tx: RawTransaction, network: NetworkType = DEFAULT_NETWORK) -> 'Transaction':
        """Requires connect to Bitcoin Blockchain APIs to set the amount for each input"""
        inps: list[UnsignableInput] = []

        for r_inp in tx.inputs:
            api = getattr(NetworkAPI, 'get_transaction_by_id' + ('_testnet' if network == 'testnet' else ''))

            if (h := api(r_inp.txid)) is None:
                raise ConnectionError  #  raise exceptions.FailedToGetTransactionData(r_inp.txid)

            inp_tx = RawTransaction.deserialize(h)
            inps.append(UnsignableInput(r_inp.txid, r_inp.vout, inp_tx.outputs[r_inp.vout].amount, r_inp.sequence))

        return cls(inps, tx.outputs, tx.version, tx.locktime)

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
    
    def default_sign(self, *, pass_unsignable: bool = False) -> None:
        """
        :param pass_unsignable: Pass inputs that don't support .default_sign() otherwise raise AssertionError
        """
        for inp in self.inputs:
            try:
                assert isinstance(inp, Input), f'supports only Input (not {type(inp).__name__})'
            except Exception as e:
                if not pass_unsignable:
                    raise e
                continue

            inp.default_sign(self)
