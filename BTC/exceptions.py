from __future__ import annotations
from abc import ABC
from decimal import Decimal
import re


class exc(Exception, ABC):
    cls: BaseException | None = Exception
    msg: str = 'default exception'

    def __new__(cls, *args, **kwargs):

        if cls.cls is None:
            return super().__new__(cls, *args, **kwargs)

        if len(args) > 0 and type(args[0]) is cls.cls:  # raise Exception (without call) == Exception(Exception())
            return args[0]

        if BaseException in cls.cls.__mro__:
            count = len(re.findall('\{\}', cls.msg))

            if count > len(args):
                args += tuple('<unknown>' for _ in range(count - (len(args) + len(kwargs))))

            return cls.cls(cls.msg.format(*args, **kwargs))

        else:
            raise TypeError(f'{cls.cls} must inherit from BaseException')


class InvalidAddress(exc):
    cls = ValueError
    msg = 'invalid address {} (with type {} and network {})'


class InvalidAddressClassType(exc):
    cls = TypeError
    msg = 'invalid address class-type - {}, use addresses.P2[KH/SH/WPKH/WSH]'


class InvalidHash160(exc):
    cls = ValueError
    msg = 'invalid hash160 - {}'


class InvalidWif(exc):
    cls = ValueError
    msg = 'invalid WIF (checksum not verified) - {}'


class InvalidScriptPubKey(exc):
    cls = ValueError
    msg = 'invalid script_pub_key - {}'


class UnsupportedAddressType(exc):
    cls = TypeError
    msg = 'unsupported type {}, supported only P2PKH, P2SH (P2SH-P2WPKH), P2WPKH, P2WSH'


class UnsupportedSegwitVersion(exc):
    cls = TypeError
    msg = 'unsupported segwit version: {}'


class DefaultSignSupportOnlyP2shP2wpkh(exc):
    cls = TypeError
    msg = 'from P2SH addresses default_sign supports P2SH-P2WPKH input only, but other type received'


class OutAmountMoreInputAmount(exc):
    cls = ArithmeticError
    msg = 'output amount ({}) more than input amount ({})'


class RemainderAddressRequired(exc):
    cls = None
    msg = 'input sum {}, output sum {}, remainder {}, need remainder address'

    def __init__(self, inp_amount: Decimal, out_amount: Decimal):
        self.args = (self.msg.format(inp_amount, out_amount, inp_amount - out_amount),)


class SighashSingleRequiresInputAndOutputWithSameIndexes(exc):
    cls = ValueError
    msg = 'sighash single signs the output with the same index as the input, the input index is {}, output with ' \
          'that index do not exists'


class SegwitHash4SignRequiresInputAmount(exc):
    cls = TypeError
    msg = 'for Transaction.get_hash4sign(input_index, ..., segwit=True) requires Input.amount is not None'


class ForDefaultSignPrivateKeyMustBeSet(exc):
    cls = ValueError
    msg = 'for Input.default_sign() need set Input.pv = PrivateKey()'


class ForDefaultSignAddressMustBeSet(exc):
    cls = ValueError
    msg = 'for Input.default_sign() need set Input.address = BitcoinAddress()'
