import pytest
from .conftest import pvobj, addrobj, msgobj
from btclib.address import *


@pytest.fixture(params=['pub', 'hash', 'string', 'pkscript'])  # address instance from hash/pub
def address(request, pv: pvobj, address_type: AddressType) -> addrobj:
    """
    It differs from the "address" fixture in conftest.py in that it has parameterization "from hash / pub".
    Has the same name for convenience.
    """
    json = pv.json[address_type.value]
    network = NetworkType.MAIN
    address = addrobj(json, address_type, pv)

    match request.param:
        case 'pub':
            ins = address.ins

        case 'hash':
            ins = type(address.ins)(bytes.fromhex(json['hash']), network=network)

        case 'string':
            ins = from_string(json['string'][network.value])

        case 'pkscript':
            ins = from_pkscript(json['pkscript'], network)

        case _:
            raise Exception()

    address.ins = ins
    return address


class TestPrivatePublicKey:
    def test_private_key_from_bytes(self, pv: pvobj):
        assert pv.ins.key.to_string().hex() == pv.json['pv']['hex']

    def test_private_key_from_wif(self, pv: pvobj, compressed, network):
        assert PrivateKey.from_wif(pv.json['pv']['wif'][compressed.string][network.value]).key.to_string().hex() == pv.json['pv']['hex']

    def test_private_key_to_wif(self, pv: pvobj, compressed, network):
        assert pv.ins.to_wif(network, pubkey_compressed=compressed.bool) == pv.json['pv']['wif'][compressed.string][network.value]

    def test_private_key_sign_message(self, message: msgobj):
        c = message.pv.pubins.compressed
        message.pv.pubins.compressed = message.json['compressed']
        assert message.pv.ins.sign_message(message.json['string']) == message.json['sig']
        message.pv.pubins.compressed = c

    def test_pub_key_creation(self, pv: pvobj, compressed):
        b = bytes.fromhex(pv.json['pub']['hex'][compressed.string])
        pub = PublicKey.from_bytes(b)
        assert pub.key.to_string() == pv.pubins.key.to_string()
        assert pub.to_bytes() == b

    def test_pub_key_to_bytes(self, pv: pvobj, compressed):
        assert pv.pubins.change_compression(compressed.bool).to_bytes().hex() == pv.json['pub']['hex'][compressed.string]

    def test_pub_key_ophash160(self, pv: pvobj, compressed):
        assert op_hash160(pv.pubins.change_compression(compressed.bool).to_bytes()).hex() == pv.json['pub']['hash160'][compressed.string]

    def test_pub_key_from_signed_message(self, message: msgobj):
        assert PublicKey.from_signed_message(message.json['sig'], message.json['string']).key.to_string() == message.pv.pubins.key.to_string()

    def test_pub_key_verify_message(self, message: msgobj):
        assert message.pv.pubins.verify_message(message.json['sig'], message.json['string'])

    def test_pub_key_verify_message_for_address(self, message: msgobj, address_type, network):
        assert message.pv.pubins.verify_message_for_address(
            message.json['sig'],
            message.json['string'],
            message.pv.pubins.change_network(network).change_compression(message.json['compressed']).get_address(address_type),
        )


class TestAddress:
    def test_pkscript(self, address: addrobj):
        assert address.ins.pkscript.serialize().hex() == address.json['pkscript']

    def test_string(self, address: addrobj, network):
        ins = address.ins.change_network(network)
        assert ins.string == str(ins) == address.json['string'][network.value]

    def test_hash(self, address: addrobj):
        assert address.ins.hash.hex() == address.json['hash']

    def test_network(self, address: addrobj):
        # start with 'mainnet' cause in address fixture ins init with "mainnet"
        assert address.ins.network == NetworkType.MAIN
        assert address.ins.change_network().network == NetworkType.TEST
