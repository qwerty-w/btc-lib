import json
from os import path
from typing import TypedDict
from functools import lru_cache
from dataclasses import dataclass

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
    pkscript: str
    amount: int
    serialized: str


class txjson(TypedDict):  # signing
    inputs: list[inpjson]
    outputs: list[outjson]
    segwit: bool
    fee: int
    version: int
    locktime: int
    id: str
    serialized: str


class coinbase_txjson(txjson):
    blockheight: int


class loadedjson(TypedDict):
    signing: list[txjson]
    coinbase: list[coinbase_txjson]


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
            pv.public.change_network(NetworkType.TEST).get_address(AddressType[self.json['type']]),
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
        self.ins = Output(Script.deserialize(self.json['pkscript']), self.json['amount'])

    @classmethod
    @lru_cache()
    def all(cls) -> list['outobj']:
        return [out for tx in txobj.all() for out in tx.outputs]


class txobj:
    with open(path.join(path.dirname(__file__), 'test_transactions.json')) as f:
        loaded: loadedjson = json.load(f)

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
    def all(cls, key: str = 'signing') -> list['txobj']:
        return [txobj(tx, i) for i, tx in enumerate(cls.loaded[key])]


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
        assert inp.ins.serialize().hex() == inp.json['serialized']


class TestOutput:
    def test_from_address(self, out: outobj):
        o = Output.from_address(address.from_string(out.json['address']), out.json['amount'])
        assert o.serialize().hex() == out.json['serialized']

    def test_copy(self, out: outobj):
        return _test_copy(out.ins, ['pkscript', 'amount', 'address'])

    def test_serialize(self, out: outobj):
        assert out.ins.serialize().hex() == out.json['serialized']


class TestTransaction:
    def test_copy(self, tx: txobj):
        _test_copy(tx.ins, ['version', 'locktime'], isnot=['inputs', 'outputs'])

    def test_is_segwit(self, tx: txobj):
        assert tx.ins.is_segwit() is tx.json['segwit']

    def test_get_id(self, tx: txobj):
        assert tx.ins.id.hex() == tx.json['id']

    def test_default_sign(self, tx: txobj):
        ins = tx.ins.copy()
        for inp_ins, inp_json in zip(ins.inputs, tx.json['inputs']):
            inp_ins.clear()
            inp_ins.default_sign(ins)  # type: ignore fixme: inp_ins type ?

            for attr in 'script', 'witness':
                assert getattr(inp_ins, attr).serialize().hex() == (inp_json.get(attr) or '')

    def test_serialize(self, tx: txobj):
        assert tx.ins.serialize().hex() == tx.json['serialized']

    def test_deserialize(self, tx: txobj):
        d = RawTransaction.deserialize(bytes.fromhex(tx.json['serialized']))

        for attr in 'inputs', 'outputs':
            assert len(getattr(d, attr)) == len(getattr(tx, attr))

        for dinp, jinp in zip(d.inputs, tx.json['inputs']):
            assert dinp.txid.hex() == jinp['txid']
            assert dinp.vout == jinp['vout']

            for attr in 'script', 'witness':
                assert getattr(dinp, attr).serialize().hex() == (jinp.get(attr) or '')

            assert dinp.serialize().hex() == jinp['serialized']

        for dout, jout in zip(d.outputs, tx.json['outputs']):
            assert dout.pkscript.serialize().hex() == jout['pkscript']
            assert dout.amount == jout['amount']

        assert d.version == tx.json['version']
        assert d.locktime == tx.json['locktime']
        assert d.serialize().hex() == tx.json['serialized']

    @pytest.mark.parametrize('cjtx', txobj.loaded['coinbase'])
    def test_coinbase_serialize_deserialize(self, cjtx):
        r = RawTransaction.deserialize(bytes.fromhex(cjtx['serialized']))
        assert r.serialize().hex() == cjtx['serialized']
        assert r.is_coinbase()
        assert isinstance(r.inputs[0], CoinbaseInput)
        assert r.inputs[0].parse_height() == cjtx['blockheight']
        assert r.id.hex() == cjtx['id']
