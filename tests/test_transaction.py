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


def inp_out_id(item):
    return f'tx{item.tx_index}-inp{item.obj_index}'


@pytest.fixture(params=get_prepared_inp_out('inputs'), ids=inp_out_id)
def inp(request):
    return request.param.copy()


@pytest.fixture(params=get_prepared_inp_out('outputs'), ids=inp_out_id)
def out(request):
    return request.param.copy()


def _test_copy(instance, eq_attrs, is_attrs):
    copied = instance.copy()

    assert copied is not instance

    for attr in eq_attrs:
        assert getattr(copied, attr) == getattr(instance, attr)

    for attr in is_attrs:
        assert getattr(copied, attr) is getattr(instance, attr)


class TestInput:
    def test_copy(self, inp):
        return _test_copy(inp.instance, ['tx_id', 'out_index', 'amount'], ['pv', 'address'])

    def test_serialize(self, inp):
        assert inp.serialized == inp.instance.serialize().hex()


class TestOutput:
    def test_copy(self, out):
        return _test_copy(out.instance, ['script_pub_key', 'amount'], ['address'])
