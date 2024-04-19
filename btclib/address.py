import base64
import hashlib
from abc import ABC, abstractmethod
from typing import Optional
from ecdsa import SigningKey, SECP256k1, VerifyingKey
from ecdsa.keys import BadSignatureError
from ecdsa.util import sigencode_der, sigencode_string, sigdecode_string
from base58check import b58encode, b58decode
from sympy import sqrt_mod

from btclib.const import PREFIXES, MAX_ORDER, SIGHASHES, P, DEFAULT_WITNESS_VERSION, DEFAULT_NETWORK, AddressType, NetworkType
from btclib.utils import sha256, r160, d_sha256, get_address_network, validate_address, \
    get_address_type, get_magic_hash, int2bytes, bytes2int, pprint_class
from btclib.script import Script
from btclib.service import NetworkAPI, Unspent
from btclib import exceptions
from btclib import bech32


class PrivateKey:
    def __init__(self, key: Optional[SigningKey] = None):
        self.key = key if key else SigningKey.generate(SECP256k1)
        self.public = PublicKey(self.key.get_verifying_key())  # type: ignore
        self.bytes = self.key.to_string()

    @classmethod
    def from_wif(cls, wif: str) -> 'PrivateKey':
        data = b58decode(wif.encode('utf-8'))
        key = data[:-4]
        checksum = data[-4:]

        h = d_sha256(key)
        if not checksum == h[0:4]:
            raise exceptions.InvalidWIF(wif)

        key = key[1:]  # network
        key = key[:-1] if len(key) > 32 else key

        return cls(SigningKey.from_string(key, SECP256k1))

    @classmethod
    def from_bytes(cls, pv_bytes: bytes):
        return cls(SigningKey.from_string(pv_bytes, SECP256k1))

    def sign_message(self, message: str, *, compressed: bool = True) -> str:
        digest = get_magic_hash(message)
        sig = self.key.sign_digest_deterministic(digest, hashlib.sha256, sigencode_string)

        rec_id = 31 if compressed else 27
        keys = VerifyingKey.from_public_key_recovery_with_digest(sig, digest, SECP256k1)
        pub_b = self.public.key.to_string()
        for i, key in enumerate(keys):
            if key.to_string() == pub_b:
                rec_id += i
                break
        return base64.b64encode(int2bytes(rec_id) + sig).decode()

    def sign_tx(self, tx_hash: bytes, sighash: int = SIGHASHES['all']) -> str:
        sig = self.key.sign_digest_deterministic(tx_hash, hashlib.sha256, sigencode_der)

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

    def to_wif(self, network: NetworkType = DEFAULT_NETWORK, *, compressed: bool = True) -> str:
        b = PREFIXES['wif'][network] + self.key.to_string()
        if compressed:
            b += b'\x01'

        h = d_sha256(b)
        checksum = h[0:4]
        wif = b58encode(b + checksum)

        return wif.decode('utf-8')

    def to_bytes(self) -> bytes:
        return self.key.to_string()


class PublicKey:
    def __init__(self, key: VerifyingKey):
        self.key: VerifyingKey = key

    @classmethod
    def from_bytes(cls, b: bytes) -> 'PublicKey':
        prefix, b = b[0:1], b[1:]

        if len(b) > 33:  # uncompressed key
            return cls(VerifyingKey.from_string(b, SECP256k1))

        if prefix not in PREFIXES['public_key']['compressed'].values():
            raise ValueError(f'unknown compression format: {prefix.hex()} {b.hex()}')

        x_coord = bytes2int(b)
        y_values: list[int] = sqrt_mod((x_coord ** 3 + 7) % P, P, all_roots=True)  # type: ignore
        even, odd = sorted(y_values, key=lambda x: x % 2 != 0)
        y_coord: int = even if prefix == PREFIXES['public_key']['compressed']['even'] else odd
        uncompressed_hex = '%0.64X%0.64X' % (x_coord, y_coord)
        return cls(VerifyingKey.from_string(bytes.fromhex(uncompressed_hex), SECP256k1))

    @classmethod
    def from_hex(cls, hex: str) -> 'PublicKey':
        return cls.from_bytes(bytes.fromhex(hex))

    @classmethod
    def from_signed_message(cls, sig_b64: str, message: str) -> 'PublicKey':
        sig = base64.b64decode(sig_b64.encode())

        if len(sig) != 65:
            raise ValueError(f'invalid signature length: {len(sig)}')

        digest = get_magic_hash(message)
        rec_id, sig = sig[0], sig[1:]

        if 27 <= rec_id <= 30:
            rec_id -= 27

        elif 31 <= rec_id <= 34:
            rec_id -= 31

        else:
            raise ValueError(f'invalid recovery id: {rec_id}')

        keys = VerifyingKey.from_public_key_recovery_with_digest(sig, digest, SECP256k1)
        return cls(keys[rec_id])

    def get_hash160(self, *, compressed: bool = True) -> bytes:
        return r160(sha256(self.to_bytes(compressed=compressed)))

    def get_address(self, type: AddressType, network: NetworkType = DEFAULT_NETWORK) -> 'Address':
        match type:
            case AddressType.P2PKH | AddressType.P2WPKH:
                _cls = { AddressType.P2PKH: P2PKH, AddressType.P2WPKH: P2WPKH }[type]
                h = self.get_hash160()

            case AddressType.P2SH_P2WPKH:
                _cls = P2SH
                h = r160(sha256(Script('OP_0', self.get_hash160()).serialize()))

            case AddressType.P2WSH:
                _cls = P2WSH
                witness_script = Script('OP_1', self.to_bytes(), 'OP_1', 'OP_CHECKMULTISIG').serialize()
                h = sha256(witness_script)

            case _:
                raise ValueError(f'invalid address type: {type}')

        return _cls.from_hash(h, network)

    @classmethod
    def verify_message_for_address(cls, sig_b64: str, message: str, address: str) -> bool:
        """
        WARNING! Default Bitcoin-Core verify message supports only P2PKH addresses. It's possible because
        one PublicKey -> one P2PKH addresses.
        With segwit addresses and P2SH address it gets hard since one PublicKey -> not one P2SH/P2WPKH/P2WSH address.
        But verify_message_for_address anyway supports all address types, it checks to
        P2SH/P2WPKH/P2WSH address was generated with PublicKey.get_address algorithm.
        This means that address could be obtained from same public key just by a different method and
        verify_message_for_address will be return False, remember this (in this situation you can use
        PublicKey.from_signed_message() and by self-checking find out that from obtained public key
        can get needed address). More details: https://github.com/bitcoin/bitcoin/issues/10542

        :param sig_b64: String signature in base64 encoding.
        :param message: Message for signature.
        :param address: Address for check
        """
        key = cls.from_signed_message(sig_b64, message)

        if not (type := get_address_type(address)) or not (network := get_address_network(address)):
            raise ValueError(f'unsupported address: {address}')

        return key.get_address(type, network).string == address

    def verify_message(self, sig_b64: str, message: str):
        magic_hash = get_magic_hash(message)
        try:
            return self.key.verify_digest(
                base64.b64decode(sig_b64.encode())[1:],
                magic_hash,
                sigdecode=sigdecode_string
            )
        except BadSignatureError:
            return False

    def to_bytes(self, *, compressed: bool = True) -> bytes:
        b: bytes = self.key.to_string()

        if not compressed:
            return PREFIXES['public_key']['uncompressed'] + b
        
        prefix = PREFIXES['public_key']['compressed']['even' if b[-1] % 2 == 0 else 'odd']
        return prefix + b[:32]


class Address(ABC):
    type: AddressType = NotImplemented

    def __init__(self, address: str):
        self.string = address

        net = get_address_network(address)
        if net is None or not validate_address(self.string, self.type, net):
            raise ValueError(f'unsupported address: {address}')
        self.network: NetworkType = net

        self.hash = self._get_hash()
        self.script_pub_key: Script = self._get_script_pub_key()

    def __str__(self):
        return self.string

    def __repr__(self):
        return pprint_class(self, [self.__str__().__repr__()])

    def __eq__(self, other: 'Address'):
        return str(self) == str(other) if isinstance(other, Address) else NotImplemented

    @classmethod
    @abstractmethod
    def from_hash(cls, hash: bytes, network: NetworkType, **kwargs) -> 'Address':
        ...

    @abstractmethod
    def _get_hash(self) -> bytes:
        ...

    @abstractmethod
    def _get_script_pub_key(self) -> Script:
        ...

    def get_info(self) -> dict:
        return getattr(NetworkAPI, 'get_address_info' + ('_testnet' if self.network == 'testnet' else ''))(self.string)

    def get_unspents(self) -> list[Unspent]:
        return getattr(NetworkAPI, 'get_unspent' + ('_testnet' if self.network == 'testnet' else ''))(self.string)
    
    def change_network(self, network: Optional[NetworkType] = None) -> 'Address':
        if network == self.network:
            return self

        network = network if network else self.network.toggle()
        return type(self).from_hash(self.hash, network)


class DefaultAddress(Address, ABC):
    @classmethod
    def from_hash(cls, hash: bytes, network: NetworkType = DEFAULT_NETWORK) -> 'DefaultAddress':
        return cls(cls._b58encode(hash, network).decode())

    @classmethod
    def _get_prefix(cls, network: NetworkType) -> bytes:
        return PREFIXES[cls.type][network]

    def _get_hash(self) -> bytes:
        return self._b58decode(self.string)

    @classmethod
    def _b58encode(cls, data: bytes, network: NetworkType) -> bytes:
        raw_address_bytes = cls._get_prefix(network) + data
        raw_address_hash = d_sha256(raw_address_bytes)
        return b58encode(raw_address_bytes + raw_address_hash[0:4])

    @staticmethod
    def _b58decode(address: str) -> bytes:
        return b58decode(address.encode())[1:-4]


class P2PKH(DefaultAddress):
    type = AddressType.P2PKH

    def _get_script_pub_key(self) -> Script:
        return Script('OP_DUP', 'OP_HASH160', self.hash, 'OP_EQUALVERIFY', 'OP_CHECKSIG')


class P2SH(DefaultAddress):
    type = AddressType.P2SH_P2WPKH

    def _get_script_pub_key(self) -> Script:
        return Script('OP_HASH160', self.hash, 'OP_EQUAL')


class SegwitAddress(Address, ABC):
    def __init__(self, address: str):
        super().__init__(address)
        self.version: int = self._bech32decode(address, self.network)[0]

    @classmethod
    def from_hash(cls, hash: bytes, network: NetworkType = DEFAULT_NETWORK, *,
                  version: int = DEFAULT_WITNESS_VERSION) -> 'SegwitAddress':
        return cls(cls._bech32encode(hash, network, version=version))

    def _get_hash(self) -> bytes:
        return self._bech32decode(self.string, self.network)[1]

    def _get_script_pub_key(self) -> Script:
        return Script('OP_0', self.hash)

    @staticmethod
    def _bech32encode(data: bytes, network: NetworkType, *, version: int) -> str:
        e = bech32.encode(PREFIXES['bech32'][network], version, list(data))
        assert e != None
        return e

    @staticmethod
    def _bech32decode(address: str, network: NetworkType) -> tuple[int, bytes]:
        ver, data = bech32.decode(PREFIXES['bech32'][network], address)

        if None in [ver, data]:
            raise ValueError(f'invalid bech32 address: {address}')
 
        return ver, bytes(data)  # type: ignore


class P2WPKH(SegwitAddress):
    type = AddressType.P2WPKH


class P2WSH(SegwitAddress):
    type = AddressType.P2WSH


def from_string(address: str) -> Address:
    _type = get_address_type(address)
    _cls = {
        AddressType.P2PKH: P2PKH,
        AddressType.P2SH_P2WPKH: P2SH,
        AddressType.P2WPKH: P2WPKH,
        AddressType.P2WSH: P2WSH
    }.get(_type)  # type: ignore

    if not _cls:
        raise exceptions.InvalidAddress(address)

    return _cls(address)

def from_script_pub_key(data: Script | str, network: NetworkType = DEFAULT_NETWORK) -> Address:
    script = data if isinstance(data, Script) else Script.deserialize(data)
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

    default_script_lens = {
        5: (p2pkh, P2PKH, 2),
        3: (p2sh, P2SH, 1),
    }
    segwit_script_lens = {
        40: P2WPKH,
        64: P2WSH
    }

    check = lambda _dict: all([script[index] == value for index, value in _dict.items()])

    if default_script_lens.get(script_len) is not None:  # if p2pkh/p2sh address
        to_check, cls, hash_index = default_script_lens[script_len]

        if check(to_check):
            return cls.from_hash(bytes.fromhex(script[hash_index]), network)

    elif script_len == 2 and check(segwit):  # if segwit address
        hs = script[1]
        return segwit_script_lens[len(hs)].from_hash(bytes.fromhex(hs))

    raise exceptions.InvalidScriptPubKey(data)
