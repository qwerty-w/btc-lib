import pytest
from addresses import *
from collections import namedtuple


_pvs_inf = [
    (
        'KyFfKRAJmKCX7kzfDkS9FUn4SWrHMK8t82XWvtkqPGN81WmffrLy',  # mainnet compressed
        'cPcenLAACNtnHCTvcAFGcoH84k9h1mEaC4fz3KDLtP28GFquTCV7',  # testnet compressed
        '5JH1XTKRR62hoqwJGaQNMVx4xAwDKCMpNyzDDfThR5PTWdvH8YP',   # mainnet uncompressed
        '923e7C8y1K6qmuSatvJHE6W2bqHvUMu1ivrAJHpCkp8WHcwoREZ',   # testnet uncompressed
        '3cada192b9679369525cac7a05b6055dac3b7760a8b8b37cb95e079648a84776',  # hex
        '02ea2b8c6913c04593764bdf8e9ff4ae113a1db15c3f80629dac87c7f0acd853b5',  # pub hex compressed
        '04ea2b8c6913c04593764bdf8e9ff4ae113a1db15c3f80629dac87c7f0acd853b'
        '5502fefe2bb47f80a121b57c79013a7d8a539d3f55198aaa70d31c94597633854',  # pub hex uncompressed
        'd11c29717053f4ec55445688f02e22e38502c443',  # pub hash160 compressed
        'f5f3f59d207345dfcbd1d8e92efe063ed6fbe22f'  # pub hash160 uncompressed

    )
]

container = namedtuple('ListContainer', 'index data')
pvs_inf = [
    {
        'wif': {
            'compressed': {
                'mainnet': d[0],
                'testnet': d[1]
            },
            'uncompressed': {
                'mainnet': d[2],
                'testnet': d[3]
            }
        },
        'hex': d[4],
        'bytes': bytes.fromhex(d[4]),
        'pub_bytes': bytes.fromhex(d[6][2:]),
        'pub_hex': {
            'compressed': d[5],
            'uncompressed': d[6]
        },
        'pub_hash160': {
            'compressed': d[7],
            'uncompressed': d[8]
        }
    } for d in _pvs_inf
]


class LoadPrivateKeys:
    _pvs_cache = []

    def __init__(self):
        pv_data = namedtuple('PrivateKeyData', 'inf pv pub')

        for pv_inf in pvs_inf:
            self._pvs_cache.append(pv_data(
                pv_inf,
                pv := PrivateKey(pv_inf['wif']['compressed']['mainnet']),
                pv.pub
            ))

    def __iter__(self):
        return iter(self._pvs_cache)


pv_data_parametrize = pytest.mark.parametrize('pv_data', LoadPrivateKeys())
compressed_parametrize = pytest.mark.parametrize('c_string, c_bool', [('compressed', True), ('uncompressed', False)])
network_parametrize = pytest.mark.parametrize('network', ['mainnet', 'testnet'])


@pv_data_parametrize
class TestPrivateKey:

    @compressed_parametrize
    @network_parametrize
    def test_private_key_creation(self, pv_data, c_string, c_bool, network):  # test PrivateKey._from_wif
        pv = PrivateKey(pv_data.inf['wif'][c_string][network])

        assert pv.to_bytes() == pv_data.inf['bytes']

    @compressed_parametrize
    @network_parametrize
    def test_private_key_to_wif(self, pv_data, c_string, c_bool, network):
        wif = pv_data.inf['wif'][c_string][network]
        pv = PrivateKey(wif)

        assert pv.to_wif(network, compressed=c_bool) == wif

    def test_pub_key_creation(self, pv_data):
        assert pv_data.pub.bytes == pv_data.inf['pub_bytes']

    @compressed_parametrize
    def test_pub_key_to_hex(self, pv_data, c_string, c_bool):
        assert pv_data.pub.to_hex(compressed=c_bool) == pv_data.inf['pub_hex'][c_string]

    @compressed_parametrize
    def test_pub_key_hash160(self, pv_data, c_string, c_bool):
        assert pv_data.pub.get_hash160(compressed=c_bool) == pv_data.inf['pub_hash160'][c_string]
