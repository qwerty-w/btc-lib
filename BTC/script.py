# Copyright (C) 2018-2020 The python-bitcoin-utils developers
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# Based on the MIT license, the base of the file was taken from
# karask/python-bitcoin-utils and modified subsequently.


from __future__ import annotations
from typing import Union, Iterable
import struct


# Bitcoin's op codes. Complete list at: https://en.bitcoin.it/wiki/Script
OP_CODES = {
    # constants
    'OP_0'                  : b'\x00',
    'OP_FALSE'              : b'\x00',
    'OP_PUSHDATA1'          : b'\x4c',
    'OP_PUSHDATA2'          : b'\x4d',
    'OP_PUSHDATA4'          : b'\x4e',
    'OP_1NEGATE'            : b'\x4f',
    'OP_1'                  : b'\x51',
    'OP_TRUE'               : b'\x51',
    'OP_2'                  : b'\x52',
    'OP_3'                  : b'\x53',
    'OP_4'                  : b'\x54',
    'OP_5'                  : b'\x55',
    'OP_6'                  : b'\x56',
    'OP_7'                  : b'\x57',
    'OP_8'                  : b'\x58',
    'OP_9'                  : b'\x59',
    'OP_10'                 : b'\x5a',
    'OP_11'                 : b'\x5b',
    'OP_12'                 : b'\x5c',
    'OP_13'                 : b'\x5d',
    'OP_14'                 : b'\x5e',
    'OP_15'                 : b'\x5f',
    'OP_16'                 : b'\x60',

    # flow control
    'OP_NOP'                : b'\x61',
    'OP_IF'                 : b'\x63',
    'OP_NOTIF'              : b'\x64',
    'OP_ELSE'               : b'\x67',
    'OP_ENDIF'              : b'\x68',
    'OP_VERIFY'             : b'\x69',
    'OP_RETURN'             : b'\x6a',

    # stack
    'OP_TOALTSTACK'         : b'\x6b',
    'OP_FROMALTSTACK'       : b'\x6c',
    'OP_IFDUP'              : b'\x73',
    'OP_DEPTH'              : b'\x74',
    'OP_DROP'               : b'\x75',
    'OP_DUP'                : b'\x76',
    'OP_NIP'                : b'\x77',
    'OP_OVER'               : b'\x78',
    'OP_PICK'               : b'\x79',
    'OP_ROLL'               : b'\x7a',
    'OP_ROT'                : b'\x7b',
    'OP_SWAP'               : b'\x7c',
    'OP_TUCK'               : b'\x7d',
    'OP_2DROP'              : b'\x6d',
    'OP_2DUP'               : b'\x6e',
    'OP_3DUP'               : b'\x6f',
    'OP_2OVER'              : b'\x70',
    'OP_2ROT'               : b'\x71',
    'OP_2SWAP'              : b'\x72',

    # splice
    # 'OP_CAT'                : b'\x7e',
    # 'OP_SUBSTR'             : b'\x7f',
    # 'OP_LEFT'               : b'\x80',
    # 'OP_RIGHT'              : b'\x81',
    'OP_SIZE'               : b'\x82',

    # bitwise logic
    # 'OP_INVERT'             : b'\x83',
    # 'OP_AND'                : b'\x84',
    # 'OP_OR'                 : b'\x85',
    # 'OP_XOR'                : b'\x86',
    'OP_EQUAL'              : b'\x87',
    'OP_EQUALVERIFY'        : b'\x88',

    # arithmetic
    'OP_1ADD'               : b'\x8b',
    'OP_1SUB'               : b'\x8c',
    # 'OP_2MUL'               : b'\x8d',
    # 'OP_2DIV'               : b'\x8e',
    'OP_NEGATE'             : b'\x8f',
    'OP_ABS'                : b'\x90',
    'OP_NOT'                : b'\x91',
    'OP_0NOTEQUAL'          : b'\x92',
    'OP_ADD'                : b'\x93',
    'OP_SUB'                : b'\x94',
    # 'OP_MUL'                : b'\x95',
    # 'OP_DIV'                : b'\x96',
    # 'OP_MOD'                : b'\x97',
    # 'OP_LSHIFT'             : b'\x98',
    # 'OP_RSHIFT'             : b'\x99',
    'OP_BOOLAND'            : b'\x9a',
    'OP_BOOLOR'             : b'\x9b',
    'OP_NUMEQUAL'           : b'\x9c',
    'OP_NUMEQUALVERIFY'     : b'\x9d',
    'OP_NUMNOTEQUAL'        : b'\x9e',
    'OP_LESSTHAN'           : b'\x9f',
    'OP_GREATERTHAN'        : b'\xa0',
    'OP_LESSTHANOREQUAL'    : b'\xa1',
    'OP_GREATERTHANOREQUAL' : b'\xa2',
    'OP_MIN'                : b'\xa3',
    'OP_MAX'                : b'\xa4',
    'OP_WITHIN'             : b'\xa5',

    # crypto
    'OP_RIPEMD160'          : b'\xa6',
    'OP_SHA1'               : b'\xa7',
    'OP_SHA256'             : b'\xa8',
    'OP_HASH160'            : b'\xa9',
    'OP_HASH256'            : b'\xaa',
    'OP_CODESEPARATOR'      : b'\xab',
    'OP_CHECKSIG'           : b'\xac',
    'OP_CHECKSIGVERIFY'     : b'\xad',
    'OP_CHECKMULTISIG'      : b'\xae',
    'OP_CHECKMULTISIGVERIFY': b'\xaf',

    # locktime
    'OP_NOP2'               : b'\xb1',
    'OP_CHECKLOCKTIMEVERIFY': b'\xb1',
    'OP_NOP3'               : b'\xb2',
    'OP_CHECKSEQUENCEVERIFY': b'\xb2'
}

CODE_OPS = {
    # constants
    b'\x00':    'OP_0'                  ,
    b'\x4c':    'OP_PUSHDATA1'          ,
    b'\x4d':    'OP_PUSHDATA2'          ,
    b'\x4e':    'OP_PUSHDATA4'          ,
    b'\x4f':    'OP_1NEGATE'            ,
    b'\x51':    'OP_1'                  ,
    b'\x52':    'OP_2'                  ,
    b'\x53':    'OP_3'                  ,
    b'\x54':    'OP_4'                  ,
    b'\x55':    'OP_5'                  ,
    b'\x56':    'OP_6'                  ,
    b'\x57':    'OP_7'                  ,
    b'\x58':    'OP_8'                  ,
    b'\x59':    'OP_9'                  ,
    b'\x5a':    'OP_10'                 ,
    b'\x5b':    'OP_11'                 ,
    b'\x5c':    'OP_12'                 ,
    b'\x5d':    'OP_13'                 ,
    b'\x5e':    'OP_14'                 ,
    b'\x5f':    'OP_15'                 ,
    b'\x60':    'OP_16'                 ,

    # flow control
    b'\x61':    'OP_NOP'                ,
    b'\x63':    'OP_IF'                 ,
    b'\x64':    'OP_NOTIF'              ,
    b'\x67':    'OP_ELSE'               ,
    b'\x68':    'OP_ENDIF'              ,
    b'\x69':    'OP_VERIFY'             ,
    b'\x6a':    'OP_RETURN'             ,

    # stack
    b'\x6b':    'OP_TOALTSTACK'         ,
    b'\x6c':    'OP_FROMALTSTACK'       ,
    b'\x73':    'OP_IFDUP'              ,
    b'\x74':    'OP_DEPTH'              ,
    b'\x75':    'OP_DROP'               ,
    b'\x76':    'OP_DUP'                ,
    b'\x77':    'OP_NIP'                ,
    b'\x78':    'OP_OVER'               ,
    b'\x79':    'OP_PICK'               ,
    b'\x7a':    'OP_ROLL'               ,
    b'\x7b':    'OP_ROT'                ,
    b'\x7c':    'OP_SWAP'               ,
    b'\x7d':    'OP_TUCK'               ,
    b'\x6d':    'OP_2DROP'              ,
    b'\x6e':    'OP_2DUP'               ,
    b'\x6f':    'OP_3DUP'               ,
    b'\x70':    'OP_2OVER'              ,
    b'\x71':    'OP_2ROT'               ,
    b'\x72':    'OP_2SWAP'              ,

    # splice
    b'\x82':    'OP_SIZE'               ,

    # bitwise logic
    b'\x87':    'OP_EQUAL'              ,
    b'\x88':    'OP_EQUALVERIFY'        ,

    # arithmetic
    b'\x8b':    'OP_1ADD'               ,
    b'\x8c':    'OP_1SUB'               ,
    b'\x8f':    'OP_NEGATE'             ,
    b'\x90':    'OP_ABS'                ,
    b'\x91':    'OP_NOT'                ,
    b'\x92':    'OP_0NOTEQUAL'          ,
    b'\x93':    'OP_ADD'                ,
    b'\x94':    'OP_SUB'                ,
    b'\x9a':    'OP_BOOLAND'            ,
    b'\x9b':    'OP_BOOLOR'             ,
    b'\x9c':    'OP_NUMEQUAL'           ,
    b'\x9d':    'OP_NUMEQUALVERIFY'     ,
    b'\x9e':    'OP_NUMNOTEQUAL'        ,
    b'\x9f':    'OP_LESSTHAN'           ,
    b'\xa0':    'OP_GREATERTHAN'        ,
    b'\xa1':    'OP_LESSTHANOREQUAL'    ,
    b'\xa2':    'OP_GREATERTHANOREQUAL' ,
    b'\xa3':    'OP_MIN'                ,
    b'\xa4':    'OP_MAX'                ,
    b'\xa5':    'OP_WITHIN'             ,

    # crypto
    b'\xa6':    'OP_RIPEMD160'          ,
    b'\xa7':    'OP_SHA1'               ,
    b'\xa8':    'OP_SHA256'             ,
    b'\xa9':    'OP_HASH160'            ,
    b'\xaa':    'OP_HASH256'            ,
    b'\xab':    'OP_CODESEPARATOR'      ,
    b'\xac':    'OP_CHECKSIG'           ,
    b'\xad':    'OP_CHECKSIGVERIFY'     ,
    b'\xae':    'OP_CHECKMULTISIG'      ,
    b'\xaf':    'OP_CHECKMULTISIGVERIFY',

    # locktime
    b'\xb1':    'OP_NOP2'               ,
    b'\xb1':    'OP_CHECKLOCKTIMEVERIFY',
    b'\xb2':    'OP_NOP3'               ,
    b'\xb2':    'OP_CHECKSEQUENCEVERIFY'
}


def prepend_compact_size(data: Union[str, bytes]):
    size = len(data)
    foo = lambda v, *, reverse=True: bytes.fromhex(format(size, v))[::-1 if reverse else 1]

    # set prefix
    if 0 <= size <= 252:
        p = foo('02x', reverse=False)

    elif 253 <= size <= 0xffff:
        p = b'\xfd' + foo('04x')

    elif 0x10000 <= size <= 0xffffffff:
        p = b'\xfe' + foo('08x')

    elif 0x100000000 <= size <= 0xffffffffffffffff:
        p = b'\xff' + foo('016x')

    else:
        raise ValueError('data size not between 0 and 0xffffffffffffffff')

    return p + data


def push_integer(i: int):

    """
    Converts integer to bytes; as signed little-endian integer
    Currently supports only positive integers
    """

    if i < 0:
        raise ValueError('integer is currently required to be positive')

    # bytes requires to represent the integer
    number_of_bytes = (i.bit_length() + 7) // 8

    # convert to little-endian bytes
    integer_bytes = i.to_bytes(number_of_bytes, byteorder='little')

    # if last bit is set then we need to add sign to signify positive
    # integer
    if i & (1 << number_of_bytes*8 - 1):
        integer_bytes += b'\x00'

    return default_op_push_data(integer_bytes)


def default_op_push_data(data: Union[str, bytes]):

    """
    Converts data to appropriate OP_PUSHDATA OP code including length

    0x01-0x4b           -> just length plus data bytes
    0x4c-0xff           -> OP_PUSHDATA1 plus 1-byte-length plus data bytes
    0x0100-0xffff       -> OP_PUSHDATA2 plus 2-byte-length plus data bytes
    0x010000-0xffffffff -> OP_PUSHDATA4 plus 4-byte-length plus data bytes

    Also note that according to standarardness rules (BIP-62) the minimum
    possible PUSHDATA operator must be used!
    """

    _data = bytes.fromhex(data) if isinstance(data, str) else data
    _len = len(_data)
    _len_b = bytes([_len])

    if _len < 0x4c:
        return _len_b + _data

    elif _len < 0xff:
        return b'\x4c' + _len_b + _data

    elif _len < 0xffff:
        return b'\x4d' + struct.pack('<H', _len) + _data

    elif _len < 0xffffffff:
        return b'\x4e' + struct.pack('<I', _len) + _data

    else:
        raise ValueError('data too large, cannot push into script')


def segwit_op_push_data(data: Union[str, bytes]):
    _data = bytes.fromhex(data) if isinstance(data, str) else data

    # prepend compact size length to data bytes
    compact_size_data = prepend_compact_size(_data)

    return compact_size_data


def _process_input_data(data: Iterable) -> list:
    _data = []

    for index, item in enumerate(data):
        if isinstance(item, str):

            if not item.startswith('OP_'):
                if len(item) % 2 != 0:
                    raise ValueError('hex expected, his length multiple of two')

                try:
                    bytes.fromhex(item)
                except ValueError:
                    raise ValueError(f'hex or opcode (OP_<...>) expected, but \'{item}\' received') from None

        elif isinstance(item, bytes):
            item = item.hex()

        else:
            raise TypeError(f'args type must be str, bytes or int, but {type(item)} received') from None

        _data.append(item)

    return _data


class Script:
    def __init__(self, *data: Union[str, bytes, int]):
        self.script = tuple(_process_input_data(data))

    def __repr__(self) -> str:
        return str(self.script)

    def __len__(self) -> int:
        return len(self.script)

    @classmethod
    def from_raw(cls, data: Union[str, bytes, list[int]], *, segwit: bool = False) -> Script:
        script = []
        bytes_ = bytes.fromhex(data) if isinstance(data, str) else bytes(data) if isinstance(data, list) else data

        i = 0
        while len(bytes_) > i:
            byte = bytes([bytes_[i]])
            byte_int = byte[0]

            # if opcode
            op = CODE_OPS.get(byte)
            if op:
                script.append(op)
                i += 1
                continue

            # if spec byte (0x4c, 0x4d, 0x4e) and not segwit
            if not segwit and byte in [b'\x4c', b'\x4d', b'\x4e']:
                size = int.from_bytes(
                    bytes_[{
                        b'\x4c': slice(i + 1),
                        b'\x4d': slice(i, i + 2),
                        b'\x4e': slice(i, i + 4)
                    }[byte]],
                    'little'
                )
                script.append(bytes_[i:i + size])
                i += size
                continue

            # other

            if byte_int < 253:
                start, size = 1, byte_int

            else:
                start = {
                    253: 2,
                    254: 4,
                    255: 8
                }[byte_int] + 1

                size = int.from_bytes(bytes_[i: i + 9][1:start][::-1], 'big')

            start += i
            i = start + size
            script.append(bytes_[start:i].hex())

        return cls(*script)

    def is_empty(self) -> bool:
        return len(self) == 0

    def _stream(self, *, segwit: bool = False) -> bytes:
        """
        Converts the script to bytes.
        If an OP code the appropriate byte is included according to:
        https://en.bitcoin.it/wiki/Script
        If not consider it data (signature, public key, public key hash, etc.) and
        and include with appropriate OP_PUSHDATA OP code plus length
        """
        script_bytes = b''
        for token in self.script:

            # add op codes directly
            if token in OP_CODES:
                script_bytes += OP_CODES[token]

            elif isinstance(token, int):
                # if integer between 0 and 16 add the appropriate op code
                script_bytes += OP_CODES['OP_' + str(token)] if 0 <= token <= 16 else push_integer(token)

            elif type(token) is int and 0 <= token <= 16:
                script_bytes += OP_CODES['OP_' + str(token)]

            # it is data, so add accordingly
            else:
                # probably add TxInputWitness which will know how to serialize
                script_bytes += segwit_op_push_data(token) if segwit else default_op_push_data(token)

        return script_bytes

    def to_bytes(self, *, segwit: bool = False) -> bytes:
        return self._stream(segwit=segwit)

    def to_hex(self, *, segwit: bool = False) -> str:
        return self.to_bytes(segwit=segwit).hex()
