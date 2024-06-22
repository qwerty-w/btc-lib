import base64
import hashlib
from abc import ABC, abstractmethod
from typing import Optional, cast
from ecdsa import SigningKey, SECP256k1, VerifyingKey
from ecdsa.keys import BadSignatureError
from ecdsa.util import sigencode_der, sigencode_string, sigdecode_string
from base58check import b58encode, b58decode
from sympy import sqrt_mod

from btclib import bech32
from btclib.script import Script
from btclib.const import PREFIXES, MAX_ORDER, SIGHASHES, P, DEFAULT_WITNESS_VERSION, DEFAULT_NETWORK, AddressType, NetworkType, OP_CODES
from btclib.utils import sha256, d_sha256, get_address_network, \
    get_address_type, get_magic_hash, int2bytes, bytes2int, pprint_class, op_hash160


class PrivateKey:
    def __init__(self, key: Optional[SigningKey] = None):
        self.key = key if key else SigningKey.generate(SECP256k1)
        self.public = PublicKey(self.key.get_verifying_key())  # type: ignore

    @classmethod
    def from_wif(cls, wif: str) -> 'PrivateKey':
        data = b58decode(wif.encode('utf8'))
        key = data[:-4]
        checksum = data[-4:]

        h = d_sha256(key)
        if not checksum == h[0:4]:
            raise ValueError(f'wif checksum verification failed {checksum.hex()} != {h[0:4].hex()}')

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

        return wif.decode('utf8')

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
            raise ValueError(f'unknown compression format (prefix) "{prefix.hex()}" (0x{prefix.hex() + b.hex()})')

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
        sig = base64.b64decode(sig_b64.encode('utf8'))

        if len(sig) != 65:
            raise ValueError(f'decoded signature length should equals 65, but {len(sig)} received')

        digest = get_magic_hash(message)
        rec_id, sig = sig[0], sig[1:]

        if 27 <= rec_id <= 30:
            rec_id -= 27

        elif 31 <= rec_id <= 34:
            rec_id -= 31

        else:
            raise ValueError(f'recovery id should be 27 <= rec_id <= 34, but {rec_id} received')

        keys = VerifyingKey.from_public_key_recovery_with_digest(sig, digest, SECP256k1)
        return cls(keys[rec_id])

    def get_address(self, type: AddressType, network: NetworkType = DEFAULT_NETWORK) -> 'BaseAddress':
        cls = {
            AddressType.P2PKH: P2PKH,
            AddressType.P2SH_P2WPKH: P2SH,
            AddressType.P2WPKH: P2WPKH,
            AddressType.P2WSH: P2WSH
        }.get(type)
        assert cls, f"unknown address type '{type}'"

        match type:
            case AddressType.P2PKH | AddressType.P2WPKH:
                return {
                    AddressType.P2PKH: P2PKH,
                    AddressType.P2WPKH: P2WPKH
                }[type].from_pubkey(self, network=network)

            case AddressType.P2SH_P2WPKH:
                script = Script('OP_0', op_hash160(self.to_bytes()))
                return P2SH(op_hash160(script.serialize()), network)

            case AddressType.P2WSH:
                script = Script('OP_1', self.to_bytes(), 'OP_1', 'OP_CHECKMULTISIG')
                return P2WSH(sha256(script.serialize()), network=network)

            case _:
                raise TypeError(f"unknown address type '{type}'")

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
            raise ValueError(f"unsupported address '{address}'")

        return key.get_address(type, network).string == address

    def verify_message(self, sig_b64: str, message: str):
        magic_hash = get_magic_hash(message)
        try:
            return self.key.verify_digest(
                base64.b64decode(sig_b64.encode('utf8'))[1:],
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


class BaseAddress(ABC):
    type: AddressType = NotImplemented

    def __init__(self, hash: bytes, network: NetworkType = DEFAULT_NETWORK):
        self.hash = hash
        self.network = network
        self.pkscript = self._to_pkscript()
        self.string = self._to_string()

    @classmethod
    @abstractmethod
    def from_string(cls, string: str) -> 'BaseAddress':
        ...

    def change_network(self, network: Optional[NetworkType] = None) -> 'BaseAddress':
        if network == self.network:
            return self

        network = network if network else self.network.toggle()
        return type(self)(self.hash, network=network)

    @abstractmethod
    def _to_pkscript(self) -> Script:
        ...

    @abstractmethod
    def _to_string(self) -> str:
        ...
    
    def __str__(self):
        return self.string

    def __repr__(self):
        return pprint_class(self, [self.__str__().__repr__()])

    def __eq__(self, other: 'BaseAddress'):
        return str(self) == str(other) if isinstance(other, BaseAddress) else NotImplemented


class LegacyAddress(BaseAddress, ABC):
    @classmethod
    def from_string(cls, string: str) -> 'LegacyAddress':
        d = b58decode(string.encode('utf8'))
        # prefix, hash, checksum
        p, h, cs = d[:1], d[1:-4], d[-4:]
        assert p in PREFIXES['legacy_reversed'], "unknown prefix '{p}'"
        type, network = PREFIXES['legacy_reversed'][p]
        assert d_sha256(p + h)[:4] == cs, f"address '{string}' checksum verification failed"
        assert type == cls.type
        return cls(h, network)

    def _to_string(self) -> str:
        b = PREFIXES[self.type][self.network] + self.hash
        cs = d_sha256(b)[:4]
        return b58encode(b + cs).decode('utf8')


class P2PKH(LegacyAddress):
    type = AddressType.P2PKH

    @classmethod
    def from_pubkey(cls, key: PublicKey, network: NetworkType = DEFAULT_NETWORK):
        return cls(op_hash160(key.to_bytes()), network)

    def _to_pkscript(self) -> Script:
        return Script('OP_DUP', 'OP_HASH160', self.hash, 'OP_EQUALVERIFY', 'OP_CHECKSIG')


class P2SH(LegacyAddress):
    type = AddressType.P2SH_P2WPKH

    def _to_pkscript(self) -> Script:
        return Script('OP_HASH160', self.hash, 'OP_EQUAL')


class SegwitAddress(BaseAddress, ABC):
    def __init__(self, hash: bytes, network: NetworkType = DEFAULT_NETWORK, version: int = DEFAULT_WITNESS_VERSION):
        self.version = version
        super().__init__(hash, network)

    @classmethod
    def from_string(cls, string: str) -> 'SegwitAddress':
        network = get_address_network(string)
        assert network, 'failed to identify network (it can be specified)'
        ver, hash = bech32.decode(PREFIXES['bech32'][network], string)
        assert None not in [ver, hash], f"bech32 decode failed '{string}'"
        return cls(bytes(cast(list[int], hash)), network, cast(int, ver))

    def _to_string(self) -> str:
        s = bech32.encode(PREFIXES['bech32'][self.network], self.version, list(self.hash))
        assert s is not None, f"bech32 encode failed '{self.hash.hex()}'"
        return s

    def _to_pkscript(self) -> Script:
        return Script('OP_0', self.hash)


class P2WPKH(SegwitAddress):
    type = AddressType.P2WPKH

    @classmethod
    def from_pubkey(cls, key: PublicKey,
                    version: int = DEFAULT_WITNESS_VERSION,
                    network: NetworkType = DEFAULT_NETWORK):
        return cls(op_hash160(key.to_bytes()), network, version)


class P2WSH(SegwitAddress):
    type = AddressType.P2WSH


def from_string(address: str) -> BaseAddress:
    type = get_address_type(address)
    cls = {
        AddressType.P2PKH: P2PKH,
        AddressType.P2SH_P2WPKH: P2SH,
        AddressType.P2WPKH: P2WPKH,
        AddressType.P2WSH: P2WSH
    }.get(type)  # type: ignore
    assert cls, f"unsupported address '{address}'"
    return cls.from_string(address)

def from_pkscript(pkscript: Script | bytes | str, network: NetworkType = DEFAULT_NETWORK) -> BaseAddress:
    script = pkscript if isinstance(pkscript, Script) else Script.deserialize(pkscript)
    length = len(script)

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

    default_script_lens: dict[int, tuple[dict[int, str], type[LegacyAddress], int]] = {
        5: (p2pkh, P2PKH, 2),
        3: (p2sh, P2SH, 1)
    }
    segwit_script_lens: dict[int, type[SegwitAddress]] = {
        20: P2WPKH,
        32: P2WSH
    }

    check = lambda _dict: all([script[index] == OP_CODES[value] for index, value in _dict.items()])

    if default_script_lens.get(length) is not None:  # if p2pkh/p2sh address
        to_check, cls, hash_index = default_script_lens[length]

        if check(to_check):
            return cls(script[hash_index], network)

    elif length == 2 and check(segwit):  # if segwit address
        hs = script[1]
        return segwit_script_lens[len(hs)](hs)

    raise ValueError(f"unsupported pkscript '{pkscript}'")
