from __future__ import annotations
from typing import Iterable

import exceptions
from const import OP_CODES, CODE_OPS
from utils import dint


class Script:
    def __init__(self, *data: str | bytes | int):
        self.script = tuple(self._validate_data(data))

    def __repr__(self) -> str:
        return f'{self.__class__.__name__}{str(self.script)}'

    def __len__(self) -> int:
        return len(self.script)

    def __eq__(self, other: Script):
        if isinstance(other, Script):
            return self.script == other.script

        return NotImplemented

    @staticmethod
    def _validate_data(raw_data: Iterable) -> list[str]:
        _data = []

        for index, item in enumerate(raw_data):
            if not len(item):
                continue

            if isinstance(item, str):

                if not item.startswith('OP_'):
                    if len(item) % 2 != 0:
                        raise exceptions.HexLengthMustBeMultipleTwo

                    try:
                        bytes.fromhex(item)
                    except ValueError:
                        raise exceptions.InvalidHexOrOpcode(item) from None

            elif isinstance(item, bytes):
                item = item.hex()

            else:
                raise exceptions.InvalidInputScriptData(type(item)) from None

            _data.append(item)

        return _data

    @classmethod
    def from_raw(cls, data: str | bytes | list[int], *, segwit: bool = False,
                 max_items_count: int = None) -> Script:
        script = []
        data = bytes.fromhex(data) if isinstance(data, str) else bytes(data) if isinstance(data, list) else data

        count = 0
        while len(data) > 0 and ((count < max_items_count) if max_items_count is not None else True):
            first_byte = data[0:1]

            # if <opcode> <data>
            op = CODE_OPS.get(first_byte)
            if op and not segwit:
                item, item_size = op, 1

            else:
                item_size, data = dint.unpack(data, increased_separator=segwit)
                item = data[:item_size]

                # if <opcode size> <opcode> <data>
                op = 'OP_0' if item_size == 0 else CODE_OPS.get(item) if item_size == 1 else None
                item = op if op is not None else item

            script.append(item)
            data = data[item_size:]

            count += 1

        return cls(*script)

    def is_empty(self) -> bool:
        return len(self) == 0

    def _stream(self, *, segwit: bool = False) -> bytes:
        serialized_data = b''

        for item in self.script:
            if item in ('00', 'OP_0'):
                serialized_data += b'\x00'
                continue

            op = OP_CODES.get(item) if item.startswith('OP_') else None
            if op:
                # <op size> + <op> if segwit else <op>
                serialized_data += (b'\x01' if segwit else b'') + op
                continue

            item = bytes.fromhex(item)
            serialized_data += dint(len(item)).pack(increased_separator=segwit) + item

        return serialized_data

    def to_bytes(self, *, segwit: bool = False) -> bytes:
        return self._stream(segwit=segwit)

    def to_hex(self, *, segwit: bool = False) -> str:
        return self.to_bytes(segwit=segwit).hex()
