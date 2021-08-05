from __future__ import annotations

import struct
from typing import Union, Iterable

from const import DEFAULT_SEQUENCE, DEFAULT_VERSION, DEFAULT_LOCKTIME, SIGHASHES, EMPTY_SEQUENCE
from utils import to_bitcoins, get_2sha256
from addresses import BitcoinAddress, PrivateKey, P2PKH, P2SH, P2WPKH, P2WSH
from script import Script
import exceptions


class Input:
    def __init__(self, pv: PrivateKey, address: BitcoinAddress, tx_id: str,
                 out_index: int, amount: int, sequence: bytes = DEFAULT_SEQUENCE):

        self.pv = pv
        self.pub = pv.pub
        self.address = address

        self.tx_id = tx_id
        self.out_index = out_index
        self.amount = amount
        self.sequence = sequence

        self.script_sig = Script()
        self.witness = Script()

    def __repr__(self):
        return f'{self.__class__.__name__}(tx_id={self.tx_id}, out_index={self.out_index})'

    def copy(self) -> Input:
        instance = Input(
            self.pv,
            self.address,
            self.tx_id,
            self.out_index,
            self.amount,
            self.sequence,
        )
        instance.script_sig = self.script_sig
        instance.witness = self.witness

        return instance

    def default_sign(self, tx: Transaction):  # default sign
        script4hash = Script('OP_DUP', 'OP_HASH160', self.pub.hash160, 'OP_EQUALVERIFY', 'OP_CHECKSIG')

        try:
            index = tx.inputs.index(self)
        except ValueError:
            raise ValueError(f'received tx has no input {repr(self)}')

        hash4sign = tx.get_hash4sign(index, script4hash)
        script_sig = Script(self.pv.sign_tx(hash4sign), self.pub.hex)

        if isinstance(self.address, P2PKH):
            self.script_sig = script_sig

        elif isinstance(self.address, P2SH):
            if self.pv.pub.get_address('P2SH-P2WPKH', self.address.network).string != self.address.string:
                raise exceptions.DefaultSignSupportOnlyP2shP2wpkh

            self.script_sig = Script(Script('OP_0', self.pub.hash160).to_hex())
            self.witness = script_sig

        elif isinstance(self.address, P2WPKH):
            self.witness = script_sig

        elif isinstance(self.address, P2WSH):  # todo
            pass

        else:
            raise exceptions.InvalidAddressClassType(type(self.address))

    def custom_sign(self, signed_script: Script, witness: Script):
        self.script_sig = signed_script if signed_script is not None else Script()
        self.witness = witness if witness is not None else Script()

    def stream(self) -> bytes:
        tx_id = bytes.fromhex(self.tx_id)[::-1]
        index = struct.pack('<L', self.out_index)
        sig = self.script_sig.to_bytes()
        sig_len = struct.pack('B', len(sig))

        return b''.join([
            tx_id,
            index,
            sig_len,
            sig,
            self.sequence
        ])


class Output:  # address: BitcoinAddress, amount: int,
    def __init__(self, address: Union[BitcoinAddress, Script], amount: int):
        self.address = address
        self.amount = amount

    def copy(self) -> Output:
        return Output(
            self.address,
            self.amount
        )

    def stream(self) -> bytes:
        amount = struct.pack('<q', self.amount)
        script_pub_key = self.address.script_pub_key.to_bytes() if isinstance(
            self.address, BitcoinAddress
        ) else self.address.to_bytes()
        script_pub_key_len = struct.pack('B', len(script_pub_key))

        return b''.join([
            amount,
            script_pub_key_len,
            script_pub_key,
        ])


class _Hash4SignGenerator:  # transaction hash for signing
    def __init__(self, tx: Transaction, input_index: int, script4hash: Script, sighash: int = SIGHASHES['all']):
        self.tx = tx
        self.index = input_index
        self.script4hash = script4hash
        self.sighash = sighash

    def get_default(self):
        tx = self.tx.copy()

        for inp in self.tx.inputs:
            inp.script_sig = Script()

        self.tx.inputs[self.index].script_sig = self.script4hash

        if (self.sighash & 0x1f) == SIGHASHES['none']:
            tx.outputs = ()

            for n, _ in enumerate(tx.inputs):
                if n != self.index:
                    tx.inputs[n].sequence = EMPTY_SEQUENCE

        elif (self.sighash & 0x1f) == SIGHASHES['single']:

            try:
                out = tx.outputs[self.index]
            except IndexError:
                raise exceptions.SighashSingleRequiresInputAndOutputWithSameIndexes(self.index) from None

            self.tx.outputs = tuple(Output(Script(), -1) for _ in range(self.index)) + (out,)

            for n, inp in enumerate(tx.inputs):
                if n != self.index:
                    inp.sequence = EMPTY_SEQUENCE

        if self.sighash & SIGHASHES['anyonecanpay']:
            tx.inputs = (tx.inputs[self.index])

        stream = self.tx.stream(exclude_witness=True) + struct.pack('<i', self.sighash)
        return get_2sha256(stream)

    def get_segwit(self):
        tx = self.tx.copy()

        base = self.sighash & 0x1f
        anyone = self.sighash & 0xf0 == SIGHASHES['anyonecanpay']
        sign_all = (base != SIGHASHES['single']) and (base != SIGHASHES['none'])

        inps, seq, outs = b'\x00' * 32, b'\x00' * 32, b'\x00' * 32

        if not anyone:
            inps = b''
            for inp in tx.inputs:
                inps += bytes.fromhex(inp.tx_id)[::-1] + struct.pack('<L', inp.out_index)

        if not anyone and sign_all:
            seq = b''
            for inp in tx.inputs:
                seq += inp.sequence

        if sign_all:
            outs = b''
            for out in tx.outputs:
                script_pub_key = out.address.script_pub_key.to_bytes()
                outs += struct.pack('<q', out.amount) + struct.pack('B', len(script_pub_key)) + script_pub_key

        elif base == SIGHASHES['single']:

            try:
                out = tx.outputs[self.index]
            except IndexError:
                raise exceptions.SighashSingleRequiresInputAndOutputWithSameIndexes(self.index) from None

            script_pub_key = out.address.script_pub_key.to_bytes()
            outs = struct.pack('<q', out.amount) + struct.pack('B', len(script_pub_key)) + script_pub_key

        inps, seq, outs = get_2sha256(inps), get_2sha256(seq), get_2sha256(outs)

        main_inp = bytes.fromhex(tx.inputs[self.index].tx_id)[::-1] + struct.pack('<L', tx.inputs[self.index].out_index)
        main_inp_seq = tx.inputs[self.index].sequence

        script4hash = self.script4hash.to_bytes()
        script4hash_len = struct.pack('B', len(script4hash))

        amount = struct.pack('<q', tx.inputs[self.index].amount)
        sighash = struct.pack('<i', self.sighash)

        raw_tx = b''.join([
            tx.version,
            inps,
            seq,
            main_inp,
            script4hash_len,
            script4hash,
            amount,
            main_inp_seq,
            outs,
            tx.locktime,
            sighash
        ])

        return get_2sha256(raw_tx)


class Transaction:
    def __init__(self, inputs: Iterable[Input], outputs: Iterable[Output],
                 fee: int, *, remainder_address: Union[str, None] = None,
                 version: bytes = DEFAULT_VERSION, locktime: bytes = DEFAULT_LOCKTIME):

        self.inputs = tuple(inputs)
        self.outputs = tuple(outputs)
        self.fee = fee
        self.remainder_address = remainder_address
        self.version = version
        self.locktime = locktime
        self.amount = sum(inp.amount for inp in inputs)

        out_amount = sum(out.amount for out in self.outputs) + self.fee
        if out_amount > self.amount:
            raise exceptions.OutAmountMoreInputAmount(self.amount, out_amount)

        elif remainder_address is None and self.amount - out_amount != 0:
            raise exceptions.RemainderAddressRequired(to_bitcoins(self.amount), to_bitcoins(out_amount))

    def copy(self):
        return Transaction(
            [inp.copy() for inp in self.inputs],
            [out.copy() for out in self.outputs],
            self.fee,
            remainder_address=self.remainder_address,
            version=self.version,
            locktime=self.locktime
        )

    def has_segwit_input(self):
        return any([inp.witness is not None for inp in self.inputs])

    def get_hash4sign(self, input_index: int, script4hash: Script, sighash: int = SIGHASHES['all']) -> bytes:
        gen = _Hash4SignGenerator(self, input_index, script4hash, sighash)
        return gen.get_segwit() if self.inputs[input_index].segwit else gen.get_default()

    def default_sign_inputs(self):  # default sign inputs
        for inp in self.inputs:
            inp.default_sign(self)

    def stream(self, *, exclude_witness: bool = False) -> bytes:
        has_segwit = False if exclude_witness else self.has_segwit_input()

        inps_len = bytes([len(self.inputs)])
        inps = b''
        for inp in self.inputs:
            inps += inp.stream()

        outs_len = bytes([len(self.outputs)])
        outs = b''
        for out in self.outputs:
            outs += out.stream()

        witnesses = b''
        if has_segwit:
            for inp in self.inputs:
                witnesses += bytes([len(inp.witness)])
                witnesses += inp.witness.to_bytes(segwit=True)

        return b''.join([
            self.version,
            b'\x00\x01' if has_segwit else b'',
            inps_len,
            inps,
            outs_len,
            outs,
            witnesses,
            self.locktime
        ])

    def serialize(self):
        return self.stream().hex()
