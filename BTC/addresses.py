from __future__ import annotations  # need for postponed evaluation of annotations (pep 563) / remove in python3.10

from abc import ABC, abstractmethod
from hashlib import sha256, new as hashlib_new
from ecdsa import SigningKey, SECP256k1, VerifyingKey
from ecdsa.util import sigencode_der
from typing import Union, Iterable
from base58check import b58encode, b58decode
from sympy import sqrt_mod

import exceptions
from const import PREFIXES, MAX_ORDER, SIGHASHES, P, DEFAULT_WITNESS_VERSION
from utils import get_2sha256, get_address_network, validate_address, get_address_type
from script import Script
from services import NetworkAPI, Unspent
import bech32


def bech32_encode(data: Iterable[int], version: int, network: str) -> str:
    return bech32.encode(PREFIXES['bech32'][network], version, data)


def bech32_decode(address: str, network: str) -> tuple:
    return bech32.decode(PREFIXES['bech32'][network], address)


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

    def get_address(self, address_type: str, network: str = 'mainnet') -> BitcoinAddress:

        if address_type in ('P2PKH', P2PKH):
            return P2PKH.from_hash160(self.hash160, network)

        elif address_type in ('P2SH', 'P2SH-P2WPKH', P2SH):
            return P2SH.from_hash160(self.hash160, network)

        elif address_type in ('P2WPKH', P2WPKH):
            return P2WPKH.from_hash160(self.hash160, network)

        elif address_type in ('P2WSH', P2WSH):
            return P2WSH.from_hash160(self.hash160, network)

        else:
            raise exceptions.UnsupportedAddressType(address_type)


class BitcoinAddress(ABC):
    @property
    @abstractmethod
    def type(self) -> str:
        ...

    def __init__(self, address: str):
        self.string = address
        self.network: str = get_address_network(address)

        if self.network is None or not validate_address(self.string, self.type, self.network):
            raise exceptions.InvalidAddress(self.string, self.type, self.network)

        self.hash = self._get_hash()
        self.script_pub_key: Script = self._get_script_pub_key()

    def __str__(self):
        return self.string

    def __repr__(self):
        return f'{self.__class__.__name__}({self.__str__().__repr__()})'

    @staticmethod
    def check_hash160(hash160: str):
        exc = exceptions.InvalidHash160(hash160)

        if len(hash160) != 40:
            raise exc

        try:
            bytes.fromhex(hash160)
        except ValueError:
            raise exc from None

    def get_unspent(self) -> list[Unspent]:
        return getattr(NetworkAPI, 'get_unspent' + ('_testnet' if self.network == 'testnet' else ''))(self.string)

    @abstractmethod
    def from_hash160(self, hash160: str, network: str) -> BitcoinAddress:
        ...

    @abstractmethod
    def _get_hash(self) -> str:
        ...

    @abstractmethod
    def _get_script_pub_key(self) -> Script:
        ...


class DefaultAddress(BitcoinAddress, ABC):
    @classmethod
    def _get_prefix(cls, network: str):
        return PREFIXES[cls.type][network]

    @classmethod
    def _from_hash160(cls, hash160: bytes, network: str) -> DefaultAddress:
        raw_address_bytes = cls._get_prefix(network) + hash160
        raw_address_hash = get_2sha256(raw_address_bytes)
        address = b58encode(raw_address_bytes + raw_address_hash[0:4]).decode('utf-8')

        return cls(address)

    def _get_hash(self) -> str:
        address_bytes = str(self).encode()
        hash160_bytes = b58decode(address_bytes)[1:-4]
        return hash160_bytes.hex()


class P2PKH(DefaultAddress):
    type = 'P2PKH'

    @classmethod
    def from_hash160(cls, hash160: str, network: str) -> P2PKH:
        cls.check_hash160(hash160)
        return cls._from_hash160(bytes.fromhex(hash160), network)

    def _get_script_pub_key(self) -> Script:
        return Script('OP_DUP', 'OP_HASH160', self.hash, 'OP_EQUALVERIFY', 'OP_CHECKSIG')


class P2SH(DefaultAddress):
    type = 'P2SH'

    @classmethod
    def from_hash160(cls, hash160: str, network: str) -> P2SH:  # hash160 -> P2SH-P2WPKH address
        cls.check_hash160(hash160)

        ripemd160 = hashlib_new('ripemd160')
        ripemd160.update(sha256(Script('OP_0', hash160).to_bytes()).digest())

        return cls._from_hash160(ripemd160.digest(), network)

    def _get_script_pub_key(self) -> Script:
        return Script('OP_HASH160', self.hash, 'OP_EQUAL')


class SegwitAddress(BitcoinAddress, ABC):
    def __init__(self, address: str):
        super().__init__(address)

        ver, _ = bech32_decode(address, self.network)
        if ver is None:
            raise exceptions.InvalidAddress(address)
        if ver != DEFAULT_WITNESS_VERSION:
            raise exceptions.UnsupportedSegwitVersion(ver)

        self.version: int = ver

    @classmethod
    def _from_hash160(cls, hash160: bytes, network: str, *, version: int) -> SegwitAddress:
        return cls(bech32_encode(list(hash160), version, network))

    def _get_hash(self) -> str:
        _, int_list = bech32_decode(self.string, self.network)
        return bytes(int_list).hex()

    def _get_script_pub_key(self) -> Script:
        return Script('OP_0', self.hash)


class P2WPKH(SegwitAddress):
    type = 'P2WPKH'

    @classmethod
    def from_hash160(cls, hash160: str, network: str) -> P2WPKH:
        cls.check_hash160(hash160)
        return cls._from_hash160(bytes.fromhex(hash160), network, version=DEFAULT_WITNESS_VERSION)


class P2WSH(SegwitAddress):
    type = 'P2WSH'

    @classmethod
    def from_hash160(cls, hash160: str, network: str) -> P2WSH:
        cls.check_hash160(hash160)

        script_bytes: bytes = Script('OP_0', hash160).to_bytes()
        hash_sha256: bytes = sha256(script_bytes).digest()

        return cls._from_hash160(hash_sha256, network, version=DEFAULT_WITNESS_VERSION)


def get_address(address: str) -> BitcoinAddress:
    addr_type = get_address_type(address)

    cls = {
        'P2PKH': P2PKH,
        'P2SH': P2SH,
        'P2WPKH': P2WPKH,
        'P2WSH': P2WSH
    }.get(addr_type, None)

    if cls is None:
        raise exceptions.InvalidAddress(address, '<unknown>', '<unknown>')

    return cls(address)
