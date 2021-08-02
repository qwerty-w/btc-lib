from __future__ import annotations  # need for postponed evaluation of annotations (pep 563) / remove in python3.10

from abc import ABC, abstractmethod
from hashlib import sha256, new as hashlib_new
from ecdsa import SigningKey, SECP256k1, VerifyingKey
from ecdsa.util import sigencode_der
from typing import Union
from base58check import b58encode, b58decode
from sympy import sqrt_mod

import exceptions
from const import PREFIXES, MAX_ORDER, SIGHASHES, P
from utils import get_2sha256


class PrivateKey:
    def __init__(self, wif: Union[str, None] = None):
        self.key = self._from_wif(wif) if wif else SigningKey.generate(curve=SECP256k1)
        self.pub = self._get_public_key()
        self.bytes = self.key.to_string()

    @staticmethod
    def _from_wif(wif: str) -> SigningKey:
        data = b58decode(wif.encode('utf-8'))
        key = data[:-4]
        checksum = data[-4:]

        h = get_2sha256(key)
        if not checksum == h[0:4]:
            raise exceptions.InvalidWif(wif)

        key = key[1:]  # network
        key = key[:-1] if len(key) > 32 else key

        return SigningKey.from_string(key, curve=SECP256k1)

    def to_wif(self, *, network: str = 'mainnet', compressed: bool = True) -> str:
        data = PREFIXES['wif'][network] + self.key.to_string() + (b'\x01' if compressed else b'')
        h = get_2sha256(data)
        checksum = h[0:4]
        wif = b58encode(data + checksum)

        return wif.decode('utf-8')

    def to_bytes(self) -> bytes:
        return self.key.to_string()

    def _get_public_key(self) -> PublicKey:
        return PublicKey('04' + self.key.get_verifying_key().to_string().hex())

    def sign_tx(self, tx_hash: bytes, sighash: int = SIGHASHES['all']):
        sig = self.key.sign_digest_deterministic(tx_hash, sigencode=sigencode_der, hashfunc=sha256)

        pref = sig[0]
        full_len = sig[1]
        der_type = sig[2]
        r_len = sig[3]
        r = sig[4:4 + r_len]
        s_len = sig[5 + r_len]
        s = sig[6 + r_len:]
        s_bigint = int(s.hex(), 16)

        half_order = MAX_ORDER // 2
        if s_bigint > half_order:

            assert s_len == 0x21
            new_s_bigint = MAX_ORDER - s_bigint
            new_s = bytes.fromhex(format(new_s_bigint, 'x').zfill(64))
            assert len(new_s) == 0x20

            s_len -= 1
            full_len -= 1
        else:
            new_s = s

        new_sig = bytes([pref, full_len, der_type, r_len]) + r + bytes([der_type, s_len]) + new_s + bytes([sighash])
        return new_sig.hex()


class PublicKey:
    def __init__(self, hex_):

        fb = hex_[:2]
        hex_b = bytes.fromhex(hex_)

        if len(hex_b) > 33:  # compressed check
            self.key = VerifyingKey.from_string(hex_b[1:], curve=SECP256k1)

        else:
            x_coord = int(hex_[2:], 16)
            y_values = sqrt_mod((x_coord ** 3 + 7) % P, P, True)

            if fb == '02':
                y_coord = y_values[0] if y_values[0] % 2 == 0 else y_values[1]

            elif fb == '03':
                y_coord = y_values[1] if y_values[0] % 2 == 0 else y_values[0]

            else:
                raise ValueError('invalid compressed format')

            uncompressed_hex = '%0.64X%0.64X' % (x_coord, y_coord)
            uncompressed_hex_b = bytes.fromhex(uncompressed_hex)

            self.key = VerifyingKey.from_string(uncompressed_hex_b, curve=SECP256k1)

        self.hex = self._to_hex()
        self.bytes = self.key.to_string()
        self.hash160 = self._get_hash160()

    def _get_hash160(self) -> str:
        h = sha256(bytes.fromhex(self.hex)).digest()
        ripemd160 = hashlib_new('ripemd160')
        ripemd160.update(h)
        return ripemd160.digest().hex()

    def _to_hex(self) -> str:
        key_hex = self.key.to_string().hex().encode()
        return ((b'02' if int(key_hex[-2:], 16) % 2 == 0 else b'03') + key_hex[:64]).decode('utf-8')

    def get_address(self, address_type: str, network: str = 'mainnet'):
        pass


class BitcoinAddress(ABC):
    pass
