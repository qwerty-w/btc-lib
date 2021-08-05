from typing import Union
from abc import ABC
from decimal import Decimal


class exc(Exception, ABC):
    cls: Union[BaseException, None] = Exception
    msg: str = 'default exception'

    def __new__(cls, *args, **kwargs):

        if cls.cls is None:
            return super().__new__(cls, *args, **kwargs)

        if isinstance(cls.cls, BaseException):
            return cls.cls(cls.msg.format(*args, **kwargs))


class InvalidAddress(exc):
    cls = ValueError
    msg = 'invalid address {} (with type {} and network {})'


class InvalidAddressClassType(exc):
    cls = TypeError
    msg = 'invalid address class-type: {}, use addresses.P2[KH/SH/WPKH/WSH]'


class InvalidHash160(exc):
    cls = ValueError
    msg = 'invalid hash160 ({})'


class InvalidWif(exc):
    cls = ValueError
    msg = 'invalid WIF ({}), checksum not verified'


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
    msg = 'output amount ({}) more than input amount {}'


class RemainderAddressRequired(exc):
    cls = None
    msg = 'input sum {}, output sum {}, remainder {}, need remainder address'

    def __init__(self, inp_amount: Decimal, out_amount: Decimal):
        self.args = (self.msg.format(inp_amount, out_amount, inp_amount - out_amount),)


class SighashSingleRequiresInputAndOutputWithSameIndexes(exc):
    cls = ValueError
    msg = 'sighash single signs the output with the same index as the input, the input index is {}, output with ' \
          'that index do not exists'
