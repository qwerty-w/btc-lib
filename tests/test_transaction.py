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
            out.script_pub_key,
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


def get_inputs():
    txs = get_txs()

    inps = []
    for tx_index, tx in enumerate(txs):
        for inp_index, inp in enumerate(tx.inputs):
            inp.set_data({
                'tx_index': tx_index,
                'inp_index': inp_index,
                'instance': tx.instance.inputs[inp_index]
            })
            inps.append(inp)

    return inps


def inp_id(item):
    return f'tx{item.tx_index}-inp{item.inp_index}'


@pytest.fixture(params=get_inputs(), ids=inp_id)
def inp(request):
    return request.param.copy()


class TestInput:
    def test_copy(self, inp):
        copied = inp.instance.copy()

        assert copied is not inp.instance

        for attr in ('tx_id', 'out_index', 'amount'):
            assert getattr(copied, attr) == getattr(inp.instance, attr)

        for attr in ('pv', 'address'):
            assert getattr(copied, attr) is getattr(inp.instance, attr)

    def test_serialize(self, inp):
        assert inp.serialized == inp.instance.serialize().hex()
