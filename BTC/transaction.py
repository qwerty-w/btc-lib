from __future__ import annotations

import struct
from typing import Union, Iterable

from const import DEFAULT_SEQUENCE, DEFAULT_VERSION, DEFAULT_LOCKTIME
from utils import to_bitcoins
from addresses import BitcoinAddress, PrivateKey, P2PKH, P2SH, P2WPKH, P2WSH
from script import Script
import exceptions


class Input:
    def __init__(self, pv: PrivateKey, address: BitcoinAddress, tx_id: str,
                 out_index: int, amount: int, segwit: bool = False,
                 sequence: bytes = DEFAULT_SEQUENCE):

        self.pv = pv
        self.pub = pv.pub
        self.address = address

        self.tx_id = tx_id
        self.out_index = out_index
        self.amount = amount
        self.segwit = segwit
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
            self.segwit,
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
            if not self.segwit:
                raise exceptions.DefaultSignNotSupportNonSegwitP2SH

            if P2SH.from_hash160(self.address.hash, self.address.network).string != self.address.string:
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
    pass


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
