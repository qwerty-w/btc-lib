from __future__ import annotations  # need for postponed evaluation of annotations (pep 563) / remove in python3.10

from abc import ABC, abstractmethod
from hashlib import sha256, new as hashlib_new
from ecdsa import SigningKey, SECP256k1, VerifyingKey
from ecdsa.util import sigencode_der
from base58check import b58encode, b58decode
from sympy import sqrt_mod

import exceptions
from const import PREFIXES, MAX_ORDER, SIGHASHES, P, DEFAULT_WITNESS_VERSION, DEFAULT_NETWORK
from utils import get_2sha256, get_address_network, validate_address, get_address_type
from script import Script
from services import NetworkAPI, Unspent
import bech32


class PrivateKey:
    def __init__(self, wif: str | None = None):
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

    def to_wif(self, network: str = DEFAULT_NETWORK, *, compressed: bool = True) -> str:
        data = PREFIXES['wif'][network] + self.key.to_string() + (b'\x01' if compressed else b'')
        h = get_2sha256(data)
        checksum = h[0:4]
        wif = b58encode(data + checksum)

        return wif.decode('utf-8')

    def to_bytes(self) -> bytes:
        return self.key.to_string()

    def _get_public_key(self) -> PublicKey:
        return PublicKey('04' + self.key.get_verifying_key().to_string().hex())

    def sign_tx(self, tx_hash: bytes, sighash: int = SIGHASHES['all']) -> str:
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
    def __init__(self, hex_: str):

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

        self.bytes = self.key.to_string()

    def get_hash160(self, *, compressed: bool = True) -> str:
        h = sha256(bytes.fromhex(self.to_hex(compressed=compressed))).digest()
        ripemd160 = hashlib_new('ripemd160')
        ripemd160.update(h)
        return ripemd160.digest().hex()

    def to_hex(self, *, compressed: bool = True) -> str:
        key_hex = self.key.to_string().hex()
        key_hex = (('02' if int(key_hex[-2:], 16) % 2 == 0 else '03') + key_hex[:64]) if compressed else '04' + key_hex
        return key_hex

    def get_address(self, address_type: str | BitcoinAddress, network: str = DEFAULT_NETWORK) -> BitcoinAddress:

        cls = {
            'P2PKH': P2PKH,
            'P2SH-P2WPKH': P2SH,
            'P2WPKH': P2WPKH,
            'P2WSH': P2WSH

        }.get(address_type) if not isinstance(address_type, BitcoinAddress) else address_type

        if cls is None:
            raise exceptions.UnsupportedAddressType(address_type)

        return cls.from_pub(self, network)


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

    @abstractmethod
    def from_pub(self, pub: PublicKey, network: str, **kwargs) -> BitcoinAddress:
        ...

    @abstractmethod
    def from_hash(self, hash_: str, network: str, **kwargs) -> BitcoinAddress:
        ...

    def get_info(self) -> dict:
        return getattr(NetworkAPI, 'get_address_info' + ('_testnet' if self.network == 'testnet' else ''))(self.string)

    def get_unspent(self) -> list[Unspent]:
        return getattr(NetworkAPI, 'get_unspent' + ('_testnet' if self.network == 'testnet' else ''))(self.string)

    @abstractmethod
    def _get_hash(self) -> str:
        ...

    @abstractmethod
    def _get_script_pub_key(self) -> Script:
        ...


class DefaultAddress(BitcoinAddress, ABC):
    @classmethod
    def from_hash(cls, hash_: str, network: str = DEFAULT_NETWORK) -> DefaultAddress:
        return cls(cls._b58encode(bytes.fromhex(hash_), network))

    @classmethod
    def _get_prefix(cls, network: str):
        return PREFIXES[cls.type][network]

    def _get_hash(self) -> str:
        return self._b58decode(self.string)

    @classmethod
    def _b58encode(cls, data: bytes, network: str) -> str:
        raw_address_bytes = cls._get_prefix(network) + data
        raw_address_hash = get_2sha256(raw_address_bytes)
        address = b58encode(raw_address_bytes + raw_address_hash[0:4]).decode('utf-8')

        return address

    @staticmethod
    def _b58decode(address: str) -> str:
        hash160_bytes = b58decode(address.encode())[1:-4]
        return hash160_bytes.hex()


class P2PKH(DefaultAddress):
    type = 'P2PKH'

    @classmethod
    def from_pub(cls, pub: PublicKey, network: str = DEFAULT_NETWORK) -> P2PKH:
        return cls(cls._b58encode(bytes.fromhex(pub.get_hash160()), network))

    def _get_script_pub_key(self) -> Script:
        return Script('OP_DUP', 'OP_HASH160', self.hash, 'OP_EQUALVERIFY', 'OP_CHECKSIG')


class P2SH(DefaultAddress):
    type = 'P2SH'

    @classmethod
    def from_pub(cls, pub: PublicKey, network: str = DEFAULT_NETWORK) -> P2SH:  # PublicKey -> P2SH-P2WPKH address
        ripemd160 = hashlib_new('ripemd160')
        ripemd160.update(sha256(Script('OP_0', pub.get_hash160()).to_bytes()).digest())

        return cls(cls._b58encode(ripemd160.digest(), network))

    def _get_script_pub_key(self) -> Script:
        return Script('OP_HASH160', self.hash, 'OP_EQUAL')


class SegwitAddress(BitcoinAddress, ABC):
    def __init__(self, address: str):
        super().__init__(address)
        self.version: int = self._bech32decode(address, self.network)[0]

    @classmethod
    def from_hash(cls, hash_: str, network: str = DEFAULT_NETWORK,
                  version: int = DEFAULT_WITNESS_VERSION) -> SegwitAddress:
        return cls(cls._bech32encode(bytes.fromhex(hash_), network, version))

    def _get_hash(self) -> str:
        _, int_list = self._bech32decode(self.string, self.network)
        return bytes(int_list).hex()

    def _get_script_pub_key(self) -> Script:
        return Script('OP_0', self.hash)

    @staticmethod
    def _bech32encode(data: bytes, network: str, version: int) -> str:
        return bech32.encode(PREFIXES['bech32'][network], version, list(data))

    @staticmethod
    def _bech32decode(address: str, network: str) -> tuple:
        return bech32.decode(PREFIXES['bech32'][network], address)


class P2WPKH(SegwitAddress):
    type = 'P2WPKH'

    @classmethod
    def from_pub(cls, pub: PublicKey, network: str = DEFAULT_NETWORK,
                 version: int = DEFAULT_WITNESS_VERSION) -> P2WPKH:
        return cls(cls._bech32encode(bytes.fromhex(pub.get_hash160()), network, version))


class P2WSH(SegwitAddress):
    type = 'P2WSH'

    @classmethod
    def from_pub(cls, pub: PublicKey, network: str = DEFAULT_NETWORK,
                 version: int = DEFAULT_WITNESS_VERSION) -> P2WSH:
        witness_script = Script('OP_1', pub.to_hex(), 'OP_1', 'OP_CHECKMULTISIG').to_bytes()
        hash_sha256 = sha256(witness_script).digest()
        return cls(cls._bech32encode(hash_sha256, network, version))


def get_address(address: str) -> BitcoinAddress:
    addr_type = get_address_type(address)

    cls = {
        'P2PKH': P2PKH,
        'P2SH': P2SH,
        'P2WPKH': P2WPKH,
        'P2WSH': P2WSH
    }.get(addr_type, None)

    if cls is None:
        raise exceptions.InvalidAddress(address)

    return cls(address)


def from_script_pub_key(data: Script | str) -> BitcoinAddress:
    script = data if isinstance(data, Script) else Script.from_raw(data)
    script_len = len(script)

    p2pkh = {
        0: 'OP_DUP',
        1: 'OP_HASH160',
        3: 'OP_EQUALVERIFY',
        4: 'OP_CHECKSIG'
    }
    p2sh = {
        0: 'OP_HASH160',
        -1: 'OP_EQUAL'
    }
    segwit = {
        0: 'OP_0'
    }

    check = lambda dict_: all([script.script[index] == value for index, value in dict_.items()])

    if script_len == 5 and check(p2pkh):
        return P2PKH.from_hash(script.script[2])

    elif script_len == 3 and check(p2sh):
        return P2SH.from_hash(script.script[1])

    elif script_len == 2 and check(segwit):

        hash_ = script.script[1]
        hash_len = len(hash_)

        if hash_len == 40:
            return P2WPKH.from_hash(hash_)

        elif hash_len == 64:
            return P2WSH.from_hash(hash_)

    raise exceptions.InvalidScriptPubKey(data)
