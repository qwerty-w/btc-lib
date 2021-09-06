import json
import pytest
from addresses import *
from collections import namedtuple


def load_pvs_inf() -> list:
    with open('pvs_inf.json') as f:
        data = json.load(f)

    for pv_inf in data:
        pv_inf['bytes'] = bytes.fromhex(pv_inf['hex'])
        pv_inf['pub']['bytes'] = bytes.fromhex(pv_inf['pub']['hex']['uncompressed'][2:])

    return data


pvs_inf = load_pvs_inf()
pv_data = namedtuple('PrivateKeyData', 'inf instance pub')
address_data = namedtuple('AddressData', 'inf instance pv')
is_c = namedtuple('IsCompressed', 'string bool')


@pytest.fixture(params=['mainnet', 'testnet'])
def network(request):
    return request.param


@pytest.fixture(params=[is_c('uncompressed', False), is_c('compressed', True)])
def compressed(request):
    return request.param


@pytest.fixture(params=pvs_inf)
def pv(request) -> pv_data:
    pv_inf = request.param
    return pv_data(pv_inf, pv := PrivateKey(pv_inf['wif']['compressed']['mainnet']), pv.pub)


class TestPrivateKey:
    def test_private_key_creation(self, pv, compressed, network):  # test PrivateKey._from_wif
        instance = PrivateKey(pv.inf['wif'][compressed.string][network])

        assert instance.to_bytes() == pv.inf['bytes']

    def test_private_key_to_wif(self, pv, compressed, network):
        wif = pv.inf['wif'][compressed.string][network]
        instance = PrivateKey(wif)

        assert instance.to_wif(network, compressed=compressed.bool) == wif

    def test_pub_key_creation(self, pv):
        assert pv.pub.bytes == pv.inf['pub']['bytes']

    def test_pub_key_to_hex(self, pv, compressed):
        assert pv.pub.to_hex(compressed=compressed.bool) == pv.inf['pub']['hex'][compressed.string]

    def test_pub_key_hash160(self, pv, compressed):
        assert pv.pub.get_hash160(compressed=compressed.bool) == pv.inf['pub']['hash160'][compressed.string]


@pytest.fixture(params=['P2PKH', 'P2SH-P2WPKH', 'P2WPKH', 'P2WSH'])
def address_type(request) -> str:
    return request.param


@pytest.fixture(params=['hash', 'pub'])  # params - from ...
def address(request, pv, address_type) -> address_data:
    from_ = request.param
    address_inf = pv.inf[address_type]
    instance = pv.pub.get_address(address_type, 'mainnet')

    if from_ == 'hash':
        instance = type(instance).from_hash(address_inf['hash'])

    return address_data(address_inf, instance, pv)


class TestAddresses:
    def test_script_pub_key(self, address):
        assert address.instance.script_pub_key.to_hex() == address.inf['script_pub_key']

    def test_string(self, address, network):
        ins = address.instance.change_network(network)
        assert ins.string == address.inf['string'][network] == str(ins)

    def test_hash(self, address):
        assert address.instance.hash == address.inf['hash']

    def test_network(self, address):
        assert address.instance.network == 'mainnet'
