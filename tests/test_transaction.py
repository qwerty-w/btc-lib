import pytest
import json
from conftest import GetterObject
from transaction import *


def prepare_tx(tx):
    instance_inps = []
    for inp in tx.inputs:
        inp_instance = Input(
            inp.tx_id,
            inp.out_index,
            inp.amount,
            pv := PrivateKey(inp.wif),
            pv.pub.get_address(inp.type, 'testnet')
        )
        inp_instance.custom_sign(inp.script, inp.witness)

        instance_inps.append(inp_instance)

    instance_outs = []
    for out in tx.outputs:
        instance_outs.append(Output(
            out.script_pub_key,  # Output from script pub key
            out.amount
        ))

    tx.set_data({'instance': Transaction(instance_inps, instance_outs, tx.version, tx.locktime)})
    return tx


def get_txs():
    with open('txs.json') as f:
        txs = json.load(f)

    return [prepare_tx(GetterObject(tx)) for tx in txs]


@pytest.fixture(params=get_txs())
def tx(request):
    return request.param.copy()


def get_prepared_inp_out(attr):
    txs = get_txs()

    prepared = []
    for tx_index, tx in enumerate(txs):
        for obj_index, obj in enumerate(getattr(tx, attr)):
            obj.set_data({
                'tx_index': tx_index,
                'obj_index': obj_index,
                'instance': getattr(tx.instance, attr)[obj_index]
            })
            prepared.append(obj)

    return prepared


def inp_out_id(name):
    def wrapper(item):
        return f'tx{item.tx_index}-{name}{item.obj_index}'

    return wrapper


@pytest.fixture(params=get_prepared_inp_out('inputs'), ids=inp_out_id('inp'))
def inp(request):
    return request.param.copy()


@pytest.fixture(params=get_prepared_inp_out('outputs'), ids=inp_out_id('out'))
def out(request):
    return request.param.copy()


def _test_copy(instance, eq_=(), is_=(), eq_not=(), is_not=()):
    copied = instance.copy()
    funcs = [
        lambda at: getattr(copied, at) == getattr(instance, at),
        lambda at: getattr(copied, at) is getattr(instance, at)
    ]

    assert copied is not instance

    for func, attrs in zip(funcs, [eq_, is_]):
        for attr in attrs:
            assert func(attr)

    for func, attrs in zip(funcs, [eq_not, is_not]):
        for attr in attrs:
            assert not func(attr)


class TestInput:
    def test_copy(self, inp):
        return _test_copy(inp.instance, ['tx_id', 'out_index', 'amount'], ['pv', 'address'])

    def test_serialize(self, inp):
        assert inp.serialized == inp.instance.serialize().hex()


class TestOutput:
    def test_copy(self, out):
        return _test_copy(out.instance, ['script_pub_key', 'amount'], ['address'])

    def test_serialize(self, out):
        assert out.serialized == out.instance.serialize().hex()


class TestTransaction:
    def test_copy(self, tx):
        _test_copy(tx, ['version', 'locktime'], is_not=['inputs', 'outputs'])

    def test_has_segwit_input(self, tx):
        assert all(inp.witness for inp in tx.inputs) is tx.instance.has_segwit_input()
