import sys
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
compressed_parametrize = pytest.mark.parametrize('compressed', [is_c('uncompressed', False), is_c('compressed', True)])
network_parametrize = pytest.mark.parametrize('network', ['mainnet', 'testnet'])


@pytest.fixture(params=pvs_inf)
def pv(request) -> pv_data:
    pv_inf = request.param
    return pv_data(pv_inf, pv := PrivateKey(pv_inf['wif']['compressed']['mainnet']), pv.pub)


@pytest.fixture(params=['P2PKH', 'P2SH-P2WPKH', 'P2WPKH', 'P2WSH'])
def address_type(request) -> str:
    return request.param


@pytest.fixture
def address(pv, address_type) -> address_data:
    return address_data(pv.inf[address_type], pv.pub.get_address(address_type), pv)


class TestPrivateKey:

    @compressed_parametrize
    @network_parametrize
    def test_private_key_creation(self, pv, compressed, network):  # test PrivateKey._from_wif
        instance = PrivateKey(pv.inf['wif'][compressed.string][network])

        assert instance.to_bytes() == pv.inf['bytes']

    @compressed_parametrize
    @network_parametrize
    def test_private_key_to_wif(self, pv, compressed, network):
        wif = pv.inf['wif'][compressed.string][network]
        instance = PrivateKey(wif)

        assert instance.to_wif(network, compressed=compressed.bool) == wif

    def test_pub_key_creation(self, pv):
        assert pv.pub.bytes == pv.inf['pub']['bytes']

    @compressed_parametrize
    def test_pub_key_to_hex(self, pv, compressed):
        assert pv.pub.to_hex(compressed=compressed.bool) == pv.inf['pub']['hex'][compressed.string]

    @compressed_parametrize
    def test_pub_key_hash160(self, pv, compressed):
        assert pv.pub.get_hash160(compressed=compressed.bool) == pv.inf['pub']['hash160'][compressed.string]


class TestAddresses:
    def test_script_pub_key(self, address):
        assert address.instance.script_pub_key.to_hex() == address.inf['script_pub_key']

    @network_parametrize
    def test_string(self, address, network):
        assert address.instance.change_network(network).string == address.inf['string'][network]

    def test_hash(self, address):
        assert address.instance.hash == address.inf['hash']
