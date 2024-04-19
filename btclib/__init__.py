from btclib import bech32, utils
from btclib.script import Script
from btclib.service import NetworkAPI
from btclib.address import PrivateKey, PublicKey, P2PKH, P2SH, P2WPKH, P2WSH, Address
from btclib.transaction import RawInput, UnsignableInput, Input, Output, RawTransaction, Transaction


__version__ = '1.0.0'


def get_unspent_inputs(*args: tuple[PrivateKey, Address]) -> list['Input']:
    return [Input.from_unspent(unspent, pv, address) for pv, address in args for unspent in address.get_unspents()]

