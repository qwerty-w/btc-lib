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
from btclib.const import PREFIXES, MAX_ORDER, SIGHASHES, P, SEGWIT_V0_WITVER, SEGWIT_V1_WITVER, \
                         DEFAULT_NETWORK, AddressType, NetworkType, OP_CODES
from btclib.utils import sha256, d_sha256, get_address_network, \
    get_address_type, get_magic_hash, int2bytes, bytes2int, pprint_class, op_hash160


class PrivateKey:
    def __init__(self,
                 key: Optional[SigningKey] = None,
                 pubkey_network: NetworkType = DEFAULT_NETWORK,
                 *,
                 pubkey_compressed: bool = True):
        self.key = key if key else SigningKey.generate(SECP256k1)
        self.public = PublicKey(
            cast(VerifyingKey, self.key.get_verifying_key()),
            network=pubkey_network,
            compressed=pubkey_compressed
        )

    @classmethod
    def from_wif(cls, wif: str) -> 'PrivateKey':
        data = b58decode(wif.encode('utf8'))
        key = data[:-4]
        checksum = data[-4:]
        assert d_sha256(key)[:4] == checksum, 'wif checksum verification failed'

        p, key = key[:1], key[1:]
        assert p in PREFIXES['wif_reversed'], f'unsupported wif prefix (0x{p.hex()})'
        network = PREFIXES['wif_reversed'][p]

        if len(key) == 33:  # compressed
            assert key[-1:] == b'\x01', f"incorrect compressed mark '{hex(key[-1])}'"
            compressed = True
            key = key[:-1]

        elif len(key) == 32:
            compressed = False

        else:
            raise ValueError(f'incorrect private key length ({len(key)})')

        return cls(SigningKey.from_string(key, SECP256k1), pubkey_network=network, pubkey_compressed=compressed)

    @classmethod
    def from_bytes(cls, b: bytes, pubkey_network: NetworkType = DEFAULT_NETWORK, pubkey_compressed: bool = True):
        return cls(SigningKey.from_string(b, SECP256k1), pubkey_network, pubkey_compressed=pubkey_compressed)

    def sign_message(self, message: str) -> str:
        digest = get_magic_hash(message)
        sig = self.key.sign_digest_deterministic(digest, hashlib.sha256, sigencode_string)

        rec_id = 31 if self.public.compressed else 27
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

    def to_wif(self,
               pubkey_network: Optional[NetworkType] = None,
               *,
               pubkey_compressed: Optional[bool] = None) -> str:
        network = self.public.network if pubkey_network is None else pubkey_network
        compressed = self.public.compressed if pubkey_compressed is None else pubkey_compressed

        b = PREFIXES['wif'][network] + self.key.to_string()
        if compressed:
            b += b'\x01'
        checksum = d_sha256(b)[:4]
        return b58encode(b + checksum).decode('utf8')

    def to_bytes(self) -> bytes:
        return self.key.to_string()


class PublicKey:
    def __init__(self, key: VerifyingKey, network: NetworkType = DEFAULT_NETWORK, *, compressed: bool = True):
        self.key = key
        self.network = network
        self.compressed = compressed

    @classmethod
    def from_bytes(cls, b: bytes, network: NetworkType = DEFAULT_NETWORK) -> 'PublicKey':
        prefix, key = b[:1], b[1:]
        assert len(key) in [32, 64], f'incorrect public key length ({len(key)})'

        if prefix == PREFIXES['public_key']['uncompressed'] or len(key) == 64:
            return cls(VerifyingKey.from_string(key, SECP256k1), compressed=False)

        assert prefix in PREFIXES['public_key']['compressed'].values(), f'unknown compressed public ' \
                                                                        f'key prefix ({prefix})'
        x_coord = bytes2int(key)
        y_values: list[int] = sqrt_mod((x_coord ** 3 + 7) % P, P, all_roots=True)  # type: ignore
        even, odd = sorted(y_values, key=lambda x: x % 2 != 0)
        y_coord: int = even if prefix == PREFIXES['public_key']['compressed']['even'] else odd
        k = x_coord.to_bytes(32) + y_coord.to_bytes(32)
        return cls(VerifyingKey.from_string(k, SECP256k1), network, compressed=True)

    @classmethod
    def from_signed_message(cls, base64sig: str, message: str,
                            network: NetworkType = DEFAULT_NETWORK) -> 'PublicKey':
        b = base64.b64decode(base64sig.encode('utf8'))
        assert len(b) == 65, f'decoded signature length should equals 65, but {len(b)} received'

        digest = get_magic_hash(message)
        recid, sig = b[0], b[1:]

        if 27 <= recid <= 30:
            recid -= 27
            compressed = False

        elif 31 <= recid <= 34:
            recid -= 31
            compressed = True

        else:
            raise ValueError(f'recovery id should be 27 <= rec_id <= 34, but {recid} received')

        keys = VerifyingKey.from_public_key_recovery_with_digest(sig, digest, SECP256k1)
        return cls(keys[recid], network=network, compressed=compressed)

    def change_compression(self, compressed: Optional[bool] = None) -> 'PublicKey':
        return self if self.compressed == compressed else PublicKey(
            self.key,
            self.network,
            compressed=not self.compressed if compressed is None else compressed
        )

    def change_network(self, network: Optional[NetworkType] = None) -> 'PublicKey':
        return self if network == self.network else PublicKey(
            self.key,
            self.network.toggle() if network is None else network,
            compressed=self.compressed
        )

    def get_address(self, type: AddressType) -> 'BaseAddress':
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
                }[type].from_pubkey(self, network=self.network)

            case AddressType.P2SH_P2WPKH:
                script = Script('OP_0', op_hash160(self.to_bytes()))
                return P2SH(op_hash160(script.serialize()), self.network)

            case AddressType.P2WSH:
                script = Script('OP_1', self.to_bytes(), 'OP_1', 'OP_CHECKMULTISIG')
                return P2WSH(sha256(script.serialize()), network=self.network)

            case _:
                raise TypeError(f"unknown address type '{type}'")

    @classmethod
    def verify_message_for_address(cls, base64sig: str, message: str, address: 'BaseAddress') -> bool:
        """
        WARNING! Default Bitcoin-Core verify message supports only P2PKH addresses. It's possible because
        one PublicKey -> one P2PKH addresses.
        With segwit addresses and P2SH address it gets hard since one PublicKey -> not one P2SH/P2WPKH/P2WSH
        address. But verify_message_for_address anyway supports all address types, it checks to
        P2SH/P2WPKH/P2WSH address was generated with PublicKey.get_address algorithm.
        This means that address could be obtained from same public key just by a different method
        (diffrent script hash) and verify_message_for_address will be return False, remember this
        (in this situation you can use PublicKey.from_signed_message() and by self-checking find
        out that from obtained public key can get needed address).
        More details: https://github.com/bitcoin/bitcoin/issues/10542

        :param base64sig: String signature in base64 encoding.
        :param message: Message for signature.
        :param address: Address for check
        """
        key = cls.from_signed_message(base64sig, message, address.network)
        return key.get_address(address.type) == address

    def verify_message(self, base64sig: str, message: str) -> bool:
        magic_hash = get_magic_hash(message)
        try:
            return self.key.verify_digest(
                base64.b64decode(base64sig.encode('utf8'))[1:],
                magic_hash,
                sigdecode=sigdecode_string
            )
        except BadSignatureError:
            return False

    def to_bytes(self) -> bytes:
        b: bytes = self.key.to_string()
        if not self.compressed:
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
        return self if network == self.network else type(self)(
            self.hash,
            network=self.network.toggle() if network is None else network
        )

    @abstractmethod
    def _to_pkscript(self) -> Script:
        ...

    @abstractmethod
    def _to_string(self) -> str:
        ...

    def __str__(self):
        return self.string

    def __repr__(self):
        return pprint_class(self, [self.__str__().__repr__()], classmethod='from_string')

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
    version: int = NotImplemented

    def __init__(self, hash: bytes, network: NetworkType = DEFAULT_NETWORK):
        super().__init__(hash, network)

    @classmethod
    def from_string(cls, string: str) -> 'SegwitAddress':
        network = get_address_network(string)
        assert network, 'failed to identify network (it can be specified)'
        ver, hash = bech32.decode(PREFIXES['bech32'][network], string)
        assert None not in [ver, hash], f"bech32 decode failed '{string}'"
        assert ver == cls.version, f'{cls.__name__}() supports only witness version {cls.version} but {ver} received'
        return cls(bytes(cast(list[int], hash)), network)

    def _to_string(self) -> str:
        s = bech32.encode(PREFIXES['bech32'][self.network], self.version, list(self.hash))
        assert s is not None, f"bech32 encode failed '{self.hash.hex()}'"
        return s

    def _to_pkscript(self) -> Script:
        return Script('OP_0', self.hash)


class P2WPKH(SegwitAddress):
    type = AddressType.P2WPKH
    version = 0

    @classmethod
    def from_pubkey(cls, key: PublicKey,
                    network: NetworkType = DEFAULT_NETWORK):
        return cls(op_hash160(key.to_bytes()), network)


class P2WSH(SegwitAddress):
    type = AddressType.P2WSH
    version = 0


class P2TR(SegwitAddress):
    type = AddressType.P2TR
    version = 1

    def _to_pkscript(self) -> Script:
        return Script('OP_1', self.hash)


def from_string(address: str) -> BaseAddress:
    type = get_address_type(address)
    cls = {
        AddressType.P2PKH: P2PKH,
        AddressType.P2SH_P2WPKH: P2SH,
        AddressType.P2WPKH: P2WPKH,
        AddressType.P2WSH: P2WSH,
        AddressType.P2TR: P2TR
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

    elif length == 2:  # segwit
        op, hs = script
        if op == OP_CODES['OP_0']:
            return segwit_script_lens[len(hs)](hs)

        elif op == OP_CODES['OP_1']:
            return P2TR(hs)

    raise ValueError(f"unsupported pkscript '{pkscript}'")
