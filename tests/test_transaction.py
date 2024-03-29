import json
from os import path

import pytest

from btclib import address
from btclib.transaction import *
from btclib.const import AddressType, NetworkType
from conftest import GetterObject


def prepare_tx(tx):
    instance_inps = []
    for inp in tx.inputs:
        inp_instance = Input(
            inp.txid,
            inp.vout,
            inp.amount,
            pv := PrivateKey.from_wif(inp.wif),
            pv.public.get_address(AddressType[inp.type.replace('-', '_')], NetworkType.TEST)
        )
        inp_instance.custom_sign(inp.script, inp.witness)

        instance_inps.append(inp_instance)

    instance_outs = []
    for out in tx.outputs:
        instance_outs.append(Output.from_address(
            address.from_string(out.address),
            out.amount
        ))

    tx.set_data({'instance': Transaction(instance_inps, instance_outs, tx.version, tx.locktime)})
    return tx


def get_txs():
    with open(path.join(path.dirname(__file__), 'txs.json')) as f:
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


def ga_eq(ins1, ins2, at):
    return getattr(ins1, at) == getattr(ins2, at)


def ga_is(ins1, ins2, at):
    return getattr(ins1, at) is getattr(ins2, at)


def _test_copy(instance, eq_=(), is_=(), eq_not=(), is_not=()):
    copied = instance.copy()
    funcs = [
        lambda at: ga_eq(copied, instance, at),
        lambda at: ga_is(copied, instance, at)
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
        return _test_copy(inp.instance, ['txid', 'vout', 'amount'], ['private', 'address'])

    def test_serialize(self, inp):
        assert inp.serialized == inp.instance.serialize().hex()


class TestOutput:
    def test_from_script_pub_key(self, out):
        fr = Output(out.script_pub_key, out.amount)
        assert fr.serialize().hex() == out.serialized == out.instance.serialize().hex()

    def test_copy(self, out):
        return _test_copy(out.instance, ['script_pub_key', 'amount', '_address'])

    def test_serialize(self, out):
        assert out.serialized == out.instance.serialize().hex()


class TestTransaction:
    def test_copy(self, tx):
        _test_copy(tx, ['version', 'locktime'], is_not=['inputs', 'outputs'])

    def test_has_segwit_input(self, tx):
        assert all(inp.witness for inp in tx.inputs) is tx.instance.has_segwit_input()

    def test_get_id(self, tx):
        assert tx.id == tx.instance.get_id()

    def test_default_sign(self, tx):
        for instance_inp, tx_inp in zip(tx.instance.inputs, tx.inputs):
            instance_inp.clear()
            instance_inp.default_sign(tx.instance)

            for attr in 'script', 'witness':
                tx_inp_val = getattr(tx_inp, attr)
                assert getattr(instance_inp, attr).serialize().hex() == ('' if tx_inp_val is None else tx_inp_val)

    def test_serialize(self, tx):
        assert tx.serialized == tx.instance.serialize().hex()

    def test_deserialize(self, tx):
        des = Transaction.deserialize(bytes.fromhex(tx.serialized))

        for attr in 'inputs', 'outputs':
            assert len(getattr(des, attr)) == len(getattr(tx, attr))

        for des_inp, tx_inp in zip(des.inputs, tx.inputs):
            for attr in 'txid', 'vout':
                assert ga_eq(des_inp, tx_inp, attr)

            for attr in 'script', 'witness':
                tx_inp_attr = getattr(tx_inp, attr)
                assert getattr(des_inp, attr).serialize().hex() == '' if tx_inp_attr is None else tx_inp_attr

        for des_out, tx_out in zip(des.outputs, tx.outputs):
            assert des_out.script_pub_key.serialize().hex() == tx_out.script_pub_key
            assert ga_eq(des_out, tx_out, 'amount')

        for attr in 'version', 'locktime':
            assert ga_eq(des, tx, attr)

        assert des.serialize().hex() == tx.serialized
