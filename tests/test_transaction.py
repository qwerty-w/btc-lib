import json
from os import path
from typing import TypedDict
from functools import lru_cache

import pytest

from btclib import address
from btclib.transaction import *
from btclib.const import AddressType, NetworkType


class inpjson(TypedDict):
    wif: str
    type: str
    txid: str
    vout: int
    amount: int
    script: str  # hex
    witness: Optional[str]
    sequence: int
    serialized: str


class outjson(TypedDict):
    address: str
    script_pub_key: str
    amount: int
    serialized: str


class txjson(TypedDict):
    inputs: list[inpjson]
    outputs: list[outjson]
    segwit: bool
    fee: int
    version: int
    locktime: int
    id: str
    serialized: str


@dataclass
class inpobj:
    json: inpjson
    tx: 'txobj'
    txindex: int
    index: int

    def __post_init__(self) -> None:
        self.ins = Input(
            bytes.fromhex(self.json['txid']),
            self.json['vout'],
            self.json['amount'],
            pv := PrivateKey.from_wif(self.json['wif']),
            pv.public.get_address(AddressType[self.json['type']], NetworkType.TEST),
            self.json['sequence'],
            Script.deserialize(self.json['script'] or b''),
            Script.deserialize(self.json['witness'] or b'', segwit=True)
        )

    @classmethod
    @lru_cache()
    def all(cls) -> list['inpobj']:
        return [inp for tx in txobj.all() for inp in tx.inputs]


@dataclass
class outobj:
    json: outjson
    tx: 'txobj'
    txindex: int
    index: int

    def __post_init__(self):
        self.ins = Output(Script.deserialize(self.json['script_pub_key']), self.json['amount'])

    @classmethod
    @lru_cache()
    def all(cls) -> list['outobj']:
        return [out for tx in txobj.all() for out in tx.outputs]


class txobj:
    with open(path.join(path.dirname(__file__), 'test_transactions.json')) as f:
        loaded: list[txjson] = json.load(f)

    def __init__(self, json: txjson, index: int) -> None:
        self.json = json
        self.index = index
        self.inputs = [inpobj(inp, self, index, i) for i, inp in enumerate(json['inputs'])]
        self.outputs = [outobj(out, self, index, i) for i, out in enumerate(json['outputs'])]
        self.ins = Transaction(
            [i.ins for i in self.inputs],
            [o.ins for o in self.outputs],
            json['version'],
            json['locktime']
        )
    @classmethod
    @lru_cache()
    def all(cls) -> list['txobj']:
        return [txobj(tx, i) for i, tx in enumerate(cls.loaded)]


@pytest.fixture(params=txobj.all())
def tx(request) -> txobj:
    return request.param


def ioid(name):
    def wrapper(item):
        return f'tx{item.txindex}-{name}{item.index}'
    return wrapper


@pytest.fixture(params=inpobj.all(), ids=ioid('inp'))
def inp(request):
    return request.param


@pytest.fixture(params=outobj.all(), ids=ioid('out'))
def out(request):
    return request.param


def aeq(ins1, ins2, at) -> bool:  # attributes ==
    return getattr(ins1, at) == getattr(ins2, at)


def ais(ins1, ins2, at) -> bool:  # attributes is
    return getattr(ins1, at) is getattr(ins2, at)


def _test_copy(ins, eq = (), is_ = (), eqnot = (), isnot = ()) -> None:
    copied = ins.copy()
    assert copied is not ins, f'copy is failed received object {copied} refers to the original {ins}'

    fs = [
        lambda a: getattr(ins, a) == getattr(copied, a),
        lambda a: getattr(ins, a) is getattr(copied, a)
    ]
    baserr = lambda a, no=False: f'attribute "{a}" of ins <{ins.__class__.__name__}> ' \
                                                     f'doesnt ==/is to copied <{copied.__class__.__name__}>' \
                                                     f'{" when this isn\'t expected" if no else ""}'
    for assertion in [True, False]:
        values = [eq, is_] if assertion else [eqnot, isnot]

        for f, attrs in zip(fs, values):
            for a in attrs:
                if assertion:
                    assert f(a), baserr(a)

                else:
                    assert not f(a), baserr(a, True)


class TestInput:
    def test_copy(self, inp: inpobj):
        return _test_copy(inp.ins, ['txid', 'vout', 'amount'], ['private', 'address'])

    def test_serialize(self, inp: inpobj):
        assert inp.json['serialized'] == inp.ins.serialize().hex()


class TestOutput:
    def test_from_address(self, out: outobj):
        o = Output.from_address(address.from_string(out.json['address']), out.json['amount'])
        assert out.json['serialized'] == o.serialize().hex()

    def test_copy(self, out: outobj):
        return _test_copy(out.ins, ['script_pub_key', 'amount', '_address'])

    def test_serialize(self, out: outobj):
        assert out.json['serialized'] == out.ins.serialize().hex()


class TestTransaction:
    def test_copy(self, tx: txobj):
        _test_copy(tx.ins, ['version', 'locktime'], isnot=['inputs', 'outputs'])

    def test_has_segwit_input(self, tx: txobj):
        assert tx.json['segwit'] is tx.ins.has_segwit_input()

    def test_get_id(self, tx: txobj):
        assert tx.json['id'] == tx.ins.get_id()

    def test_default_sign(self, tx: txobj):
        for inp_ins, inp_json in zip(tx.ins.inputs, tx.json['inputs']):
            inp_ins.clear()
            inp_ins.default_sign(tx.ins)  # type: ignore

            for attr in 'script', 'witness':
                assert (inp_json.get(attr) or '') == getattr(inp_ins, attr).serialize().hex()

    def test_serialize(self, tx: txobj):
        assert tx.json['serialized'] == tx.ins.serialize().hex()

    def test_deserialize(self, tx: txobj):
        d = RawTransaction.deserialize(bytes.fromhex(tx.json['serialized']))

        for attr in 'inputs', 'outputs':
            assert len(getattr(d, attr)) == len(getattr(tx, attr))

        for jinp, dinp in zip(tx.json['inputs'], d.inputs):
            assert jinp['txid'] == dinp.txid.hex()
            assert jinp['vout'] == dinp.vout

            for attr in 'script', 'witness':
                assert (jinp.get(attr) or '') == getattr(dinp, attr).serialize().hex()

        for jout, dout in zip(tx.json['outputs'], d.outputs):
            assert jout['script_pub_key'] == dout.script_pub_key.serialize().hex()
            assert jout['amount'] == dout.amount

        assert tx.json['version'] == d.version
        assert tx.json['locktime'] == d.locktime
        assert tx.json['serialized'] == d.serialize().hex()
