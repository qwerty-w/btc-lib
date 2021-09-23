from __future__ import annotations

from abc import abstractmethod
from typing import Iterable, Protocol
import json

from const import DEFAULT_SEQUENCE, DEFAULT_VERSION, DEFAULT_LOCKTIME, SIGHASHES, EMPTY_SEQUENCE, NEGATIVE_SATOSHI
from utils import get_2sha256, uint32, uint64, sint64, dint
from addresses import BitcoinAddress, PrivateKey, P2PKH, P2SH, P2WPKH, P2WSH, from_script_pub_key
from script import Script
from services import Unspent, NetworkAPI
import exceptions


def get_inputs(*args: list[PrivateKey, BitcoinAddress] | tuple[PrivateKey, BitcoinAddress]) -> list[Input]:
    return [Input.from_unspent(unspent, pv, address) for pv, address in args for unspent in address.get_unspent()]


class SupportsDump(Protocol):
    @abstractmethod
    def as_dict(self) -> dict:
        ...

    @abstractmethod
    def as_json(self, value: dict | list, indent: int = None) -> str:
        return json.dumps(value, indent=indent)


class SupportsSerialize(Protocol):
    @abstractmethod
    def serialize(self) -> str | bytes:
        ...


class SupportsCopy(Protocol):
    @abstractmethod
    def copy(self):
        ...


class Input(SupportsDump, SupportsSerialize, SupportsCopy):
    def __init__(self, tx_id: str, out_index: int, amount: int | None = None, pv: PrivateKey | None = None,
                 address: BitcoinAddress | None = None, sequence: int = DEFAULT_SEQUENCE):
        """
        :param tx_id: Transaction hex.
        :param out_index: Unspent output index in transaction.
        :param amount: Transaction amount.
        :param pv: Private Key, can be None if .default_sign() won't be used.
        :param address: Bitcoin address, can be None as well as pv.
        :param sequence: Sequence (more in Bitcoin Core documentation).
        """
        self.pv = pv
        self.pub = pv.pub if pv is not None else None
        self.address = address

        self.tx_id = tx_id
        self.out_index = uint32(out_index)
        self.amount = uint64(amount) if amount is not None else amount
        self.sequence = uint32(sequence)

        self.script = Script()
        self.witness = Script()

    def __repr__(self):
        args = {
            'tx_id': self.tx_id,
            'out_index': self.out_index
        }

        if self.address:
            args['address'] = self.address
        if self.sequence != DEFAULT_SEQUENCE:
            args['sequence'] = self.sequence

        return '{}({})'.format(self.__class__.__name__, ' , '.join(f'{name}={value}' for name, value in args.items()))

    def as_dict(self, *, address: bool = True, script: bool = True, witness: bool = True) -> dict:
        items = [
            ('tx_id', self.tx_id),
            ('out_index', self.out_index)
        ]

        if self.amount is not None:
            items.append(('amount', self.amount))

        if address and self.address:
            items = [('address', self.address.string), *items]

        if script and not self.script.is_empty():
            items.append(('script', self.script.to_hex()))

        if witness and not self.witness.is_empty():
            items.append(('witness', self.witness.to_hex()))

        items.append(('sequence', self.sequence))
        return dict(items)

    def as_json(self, *, indent: int = None, **kwargs) -> str:
        return super().as_json(self.as_dict(**kwargs), indent=indent)

    @classmethod
    def from_unspent(cls, unspent: Unspent, pv: PrivateKey | None = None,
                     address: BitcoinAddress | None = None, sequence: int = DEFAULT_SEQUENCE) -> Input:
        return cls(unspent.txid, unspent.txindex, unspent.amount, pv, address, sequence)

    def copy(self) -> Input:
        instance = Input(
            self.tx_id,
            self.out_index,
            self.amount,
            self.pv,
            self.address,
            self.sequence,
        )
        instance.script = self.script
        instance.witness = self.witness

        return instance

    def default_sign(self, tx: Transaction):  # default sign
        """
        Default sign supports P2PKH, P2SH-P2WPKH, P2WPKH, P2WSH.
        The last three use a witness (tx.get_hash4sign(segwit=True))
        """
        if not isinstance(self.pv, PrivateKey):
            raise exceptions.ForDefaultSignPrivateKeyMustBeSet
        if not isinstance(self.address, BitcoinAddress):
            raise exceptions.ForDefaultSignAddressMustBeSet

        try:
            index = tx.inputs.index(self)
        except ValueError:
            raise ValueError(f'received tx has no input {repr(self)}') from None

        if isinstance(self.address, P2WSH):
            witness_script = Script('OP_1', self.pub.to_hex(), 'OP_1', 'OP_CHECKMULTISIG')
            hash4sign = tx.get_hash4sign(index, witness_script, segwit=True)
            sig = self.pv.sign_tx(hash4sign)
            self.witness = Script('OP_0', sig, witness_script.to_hex())

            return

        script4hash = Script('OP_DUP', 'OP_HASH160', self.pub.get_hash160(), 'OP_EQUALVERIFY', 'OP_CHECKSIG')
        hash4sign = tx.get_hash4sign(index, script4hash, segwit=False if isinstance(self.address, P2PKH) else True)
        sig = Script(self.pv.sign_tx(hash4sign), self.pub.to_hex())

        if isinstance(self.address, P2PKH):
            self.script = sig

        elif isinstance(self.address, P2SH):  # supports only P2SH-P2WPKH
            if self.pub.get_address('P2SH-P2WPKH', self.address.network).string != self.address.string:
                raise exceptions.DefaultSignSupportOnlyP2shP2wpkh

            self.script = Script(Script('OP_0', self.pub.get_hash160()).to_hex())
            self.witness = sig

        elif isinstance(self.address, P2WPKH):
            self.witness = sig

        else:
            raise exceptions.InvalidAddressClassType(type(self.address))

    def custom_sign(self, signed_script: Script | str, witness: Script | str):
        for name, value in [('script', signed_script), ('witness', witness)]:
            value = Script() if value is None else Script.from_raw(value) if isinstance(value, str) else value
            setattr(self, name, value)

    def serialize(self) -> bytes:
        sig = self.script.to_bytes()
        sig_size = dint(len(sig)).pack()

        return b''.join([
            bytes.fromhex(self.tx_id)[::-1],
            self.out_index.pack(),
            sig_size,
            sig,
            self.sequence.pack()
        ])


class Output(SupportsDump, SupportsSerialize, SupportsCopy):
    def __init__(self, address_or_script_pub_key: BitcoinAddress | Script | str, amount: int):
        instance = address_or_script_pub_key

        if isinstance(instance, (str, Script)):
            try:
                instance = from_script_pub_key(instance)
            except:
                instance = instance if isinstance(instance, Script) else Script.from_raw(instance)

        elif not isinstance(instance, BitcoinAddress):
            raise exceptions.InvalidAddressClassType(type(instance))

        self.address = instance if isinstance(instance, BitcoinAddress) else None
        self.script_pub_key = self.address.script_pub_key if isinstance(instance, BitcoinAddress) else instance
        self.amount = uint64(amount) if amount >= 0 else sint64(amount)

    def __repr__(self):
        args = dict([
            ('script_pub_key', self.script_pub_key) if self.address is None else ('address', self.address),
            ('amount', self.amount)
        ])
        return '{}({})'.format(self.__class__.__name__, ' , '.join(f'{name}={value}' for name, value in args.items()))

    def as_dict(self, *, address_as_script: bool = False) -> dict:
        dict_ = {}

        if self.address is not None and not address_as_script:
            dict_['address'] = self.address.string

        else:
            dict_['script_pub_key'] = self.script_pub_key.to_hex()

        dict_['amount'] = self.amount
        return dict_

    def as_json(self, *, indent: int | None = None, **kwargs) -> str:
        return super().as_json(self.as_dict(**kwargs), indent=indent)

    def copy(self) -> Output:
        return Output(
            self.address if self.address is not None else self.script_pub_key,
            self.amount
        )

    def serialize(self) -> bytes:
        script_pub_key = self.script_pub_key.to_bytes()
        script_pub_key_size = dint(len(script_pub_key)).pack()

        return b''.join([
            self.amount.pack(),
            script_pub_key_size,
            script_pub_key,
        ])


class _Hash4SignGenerator:  # hash for sign
    def __init__(self, tx: Transaction, input_index: int, script4hash: Script, sighash: int = SIGHASHES['all']):
        self.tx = tx
        self.index = input_index
        self.script4hash = script4hash  # script for hash for sign
        self.sighash = uint32(sighash)

    def get_default(self) -> bytes:
        tx = self.tx.copy()

        for inp in tx.inputs:
            inp.script = Script()

        tx.inputs[self.index].script = self.script4hash

        if (self.sighash & 0x1f) == SIGHASHES['none']:
            tx.outputs = ()

            for n, _ in enumerate(tx.inputs):
                if n != self.index:
                    tx.inputs[n].sequence = uint32(EMPTY_SEQUENCE)

        elif (self.sighash & 0x1f) == SIGHASHES['single']:

            try:
                out = tx.outputs[self.index]
            except IndexError:
                raise exceptions.SighashSingleRequiresInputAndOutputWithSameIndexes(self.index) from None

            tx.outputs = tuple(Output(Script(), NEGATIVE_SATOSHI) for _ in range(self.index)) + (out,)

            for n, inp in enumerate(tx.inputs):
                if n != self.index:
                    inp.sequence = uint32(EMPTY_SEQUENCE)

        if self.sighash & SIGHASHES['anyonecanpay']:
            tx.inputs = (tx.inputs[self.index])

        serialized = tx.serialize(to_bytes=True, exclude_witnesses=True) + self.sighash.pack()
        return get_2sha256(serialized)

    def get_segwit(self) -> bytes:
        tx = self.tx.copy()

        base = self.sighash & 0x1f
        anyone = self.sighash & 0xf0 == SIGHASHES['anyonecanpay']
        sign_all = (base != SIGHASHES['single']) and (base != SIGHASHES['none'])

        inps, seq, outs = b'\x00' * 32, b'\x00' * 32, b'\x00' * 32

        if not anyone:
            inps = b''
            for inp in tx.inputs:
                inps += bytes.fromhex(inp.tx_id)[::-1] + inp.out_index.pack()

            if sign_all:
                seq = b''
                for inp in tx.inputs:
                    seq += inp.sequence.pack()

        if sign_all:
            outs = b''.join(out.serialize() for out in tx.outputs)

        elif base == SIGHASHES['single']:

            try:
                out = tx.outputs[self.index]
            except IndexError:
                raise exceptions.SighashSingleRequiresInputAndOutputWithSameIndexes(self.index) from None

            outs = out.serialize()

        inps, seq, outs = get_2sha256(inps), get_2sha256(seq), get_2sha256(outs)

        main_inp = bytes.fromhex(tx.inputs[self.index].tx_id)[::-1]
        main_inp += tx.inputs[self.index].out_index.pack()
        main_inp_seq = tx.inputs[self.index].sequence.pack()

        script4hash = self.script4hash.to_bytes()
        script4hash_size = dint(len(script4hash)).pack()

        if tx.inputs[self.index].amount is None:
            raise exceptions.SegwitHash4SignRequiresInputAmount

        ver = tx.version.pack()
        locktime = tx.locktime.pack()
        amount = tx.inputs[self.index].amount.pack()
        sighash = self.sighash.pack()

        raw_tx = b''.join([
            ver,
            inps,
            seq,
            main_inp,
            script4hash_size,
            script4hash,
            amount,
            main_inp_seq,
            outs,
            locktime,
            sighash
        ])

        return get_2sha256(raw_tx)


class _TransactionDeserializer:
    def __init__(self, tx_hex: str):
        self.hex = tx_hex
        self.raw = bytes.fromhex(tx_hex)

    def is_segwit_tx(self) -> bool:
        return self.raw[4] == 0

    def pop(self, value: int = None) -> bytes:

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

    def deserialize(self) -> dict[str, str | int | list[dict]]:
        segwit = self.is_segwit_tx()
        data = {
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
                'tx_id': self.pop(32)[::-1].hex(),
                'out_index': uint32.unpack(self.pop(4)),
                'script': Script.from_raw(self.pop(self.pop_size())).to_hex(),
                'sequence': uint32.unpack(self.pop(4))
            })

        # outputs
        outs_count = self.pop_size()
        for _ in range(outs_count):
            amount = uint64.unpack(self.pop(8))
            data['outputs'].append({
                'script_pub_key': self.pop(self.pop_size()).hex(),
                'amount': amount
            })

        # witnesses
        if segwit:
            for inp_index in range(inps_count):
                items_count = self.pop_size()
                script = Script.from_raw(self.raw, segwit=True, max_items_count=items_count)
                data['inputs'][inp_index]['witness'] = script.to_hex(segwit=True)

                # sort order
                seq = data['inputs'][inp_index].pop('sequence')
                data['inputs'][inp_index]['sequence'] = seq

                self.pop(len(script.to_bytes(segwit=True)))

        return data


class Transaction(SupportsDump, SupportsSerialize, SupportsCopy):
    def __init__(self, inputs: Iterable[Input], outputs: Iterable[Output],
                 version: int = DEFAULT_VERSION, locktime: int = DEFAULT_LOCKTIME):

        self.inputs = tuple(inputs)
        self.outputs = tuple(outputs)
        self.version = uint32(version)
        self.locktime = uint32(locktime)
        self.amount = sum(values) if None not in (values := [inp.amount for inp in self.inputs]) else None
        self.fee = self.amount - sum(out.amount for out in self.outputs) if self.amount is not None else None

    def __repr__(self):
        return str(self.as_dict())

    def as_dict(self, *, inp_address: bool = True, scripts: bool = True,
                witnesses: bool = True, out_address_as_script: bool = False) -> dict:
        return {
            'inputs': [inp.as_dict(address=inp_address, script=scripts, witness=witnesses) for inp in self.inputs],
            'outputs': [out.as_dict(address_as_script=out_address_as_script) for out in self.outputs],
            'fee': self.fee if self.fee is not None else '<unknown>',
            'version': self.version,
            'locktime': self.locktime
        }

    def as_json(self, *, indent: int | None = None, **kwargs) -> str:
        return super().as_json(self.as_dict(**kwargs), indent=indent)

    def copy(self) -> Transaction:
        return Transaction(
            [inp.copy() for inp in self.inputs],
            [out.copy() for out in self.outputs],
            self.version,
            self.locktime
        )

    def has_segwit_input(self) -> bool:
        return any([not inp.witness.is_empty() for inp in self.inputs])

    def set_amounts(self, tx_network: str):
        """
        Set self.amount and self.fee, for it may need connect to
        Bitcoin Blockchain APIs (if one in inputs have Input.amount = None).
        Also set Input.amount, if before he was None.
        """
        amount = 0
        for inp in self.inputs:

            if inp.amount is None:
                api = getattr(NetworkAPI, 'get_transaction_by_id' + ('_testnet' if tx_network == 'testnet' else ''))
                inp_tx_hex = api(inp.tx_id)

                if inp_tx_hex is None:
                    raise exceptions.FailedToGetTransactionData(inp.tx_id)

                inp_tx = Transaction.deserialize(inp_tx_hex)
                inp.amount = uint64(inp_tx.outputs[inp.out_index].amount)

            amount += inp.amount

        self.amount = amount
        self.fee = amount - sum(out.amount for out in self.outputs)

    def get_id(self) -> str:
        return get_2sha256(self.serialize(to_bytes=True, exclude_witnesses=True))[::-1].hex()

    def get_hash4sign(self, input_index: int, script4hash: Script, *,
                      segwit: bool, sighash: int = SIGHASHES['all']) -> bytes:
        """
        :param input_index:
        :param script4hash: Script which will be used in default input script field.
        :param segwit: If hash4sign needed for script in witness - use segwit=True.
                       Else if using default input script - False.
        :param sighash: Signature Hash (more in Bitcoin Core documentation).
        :return: Hash for private key signing.
        """
        gen = _Hash4SignGenerator(self, input_index, script4hash, sighash)
        return gen.get_segwit() if segwit else gen.get_default()

    def default_sign_inputs(self):  # default sign inputs
        for inp in self.inputs:
            inp.default_sign(self)

    @classmethod
    def deserialize(cls, tx_hex: str, *, to_dict: bool = False) -> dict | Transaction:
        tx_dict = _TransactionDeserializer(tx_hex).deserialize()

        if to_dict:
            return tx_dict

        # convert dict inputs to Input objects
        inputs = []
        for inp_dict in tx_dict['inputs']:
            inp_instance = Input(
                inp_dict['tx_id'],
                inp_dict['out_index'],
                sequence=inp_dict['sequence']
            )
            inp_instance.custom_sign(
                Script.from_raw(inp_dict['script']),
                Script.from_raw(inp_dict.get('witness', ''), segwit=True)
            )

            inputs.append(inp_instance)

        # convert dict outputs to Output objects
        outputs = []
        for out_dict in tx_dict['outputs']:
            outputs.append(Output(out_dict['script_pub_key'], out_dict['amount']))

        tx_args = {
            'inputs': inputs,
            'outputs': outputs,
            'version': tx_dict['version'],
            'locktime': tx_dict['locktime']
        }
        return Transaction(**tx_args)

    def serialize(self, *, to_bytes: bool = False, exclude_witnesses: bool = False) -> str | bytes:
        has_segwit = False if exclude_witnesses else self.has_segwit_input()

        inps_count = dint(len(self.inputs)).pack()
        inps = b''
        for inp in self.inputs:
            inps += inp.serialize()

        outs_count = dint(len(self.outputs)).pack()
        outs = b''
        for out in self.outputs:
            outs += out.serialize()

        witnesses = b''
        if has_segwit:
            for inp in self.inputs:
                witnesses += dint(len(inp.witness)).pack()
                witnesses += inp.witness.to_bytes(segwit=True)

        serialized_tx = b''.join([
            self.version.pack(),
            b'\x00\x01' if has_segwit else b'',  # segwit mark
            inps_count,
            inps,
            outs_count,
            outs,
            witnesses,
            self.locktime.pack()
        ])
        return serialized_tx.hex() if not to_bytes else serialized_tx
