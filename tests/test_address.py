import pytest
from .conftest import pvobj, addrobj, msgobj
from btclib.address import *


@pytest.fixture(params=['pub', 'hash', 'string', 'scriptPubKey'])  # address instance from hash/pub
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
            ins = type(address.ins).from_hash(bytes.fromhex(json['hash']), network)

        case 'string':
            ins = from_string(json['string'][network.value])

        case 'scriptPubKey':
            ins = from_script_pub_key(json['script_pub_key'], network)

        case _:
            raise Exception()

    address.ins = ins
    return address


class TestPrivatePublicKey:
    def test_private_key_from_bytes(self, pv: pvobj):
        assert pv.json['pv']['hex'] == pv.ins.key.to_string().hex()

    def test_private_key_from_wif(self, pv: pvobj, compressed, network):
        assert pv.json['pv']['hex'] == PrivateKey.from_wif(pv.json['pv']['wif'][compressed.string][network.value]).key.to_string().hex()

    def test_private_key_to_wif(self, pv: pvobj, compressed, network):
        assert pv.json['pv']['wif'][compressed.string][network.value] == pv.ins.to_wif(network, compressed=compressed.bool)

    def test_private_key_sign_message(self, message: msgobj):
        assert message.json['sig'] == message.pv.ins.sign_message(message.json['string'], compressed=message.json['compressed'])

    def test_pub_key_creation(self, pv: pvobj, compressed):
        b = bytes.fromhex(pv.json['pub']['hex'][compressed.string])
        pub = PublicKey.from_bytes(b)
        assert pv.pubins.key.to_string() == pub.key.to_string()
        assert b == pub.to_bytes(compressed=compressed.bool)

    def test_pub_key_to_bytes(self, pv: pvobj, compressed):
        assert pv.json['pub']['hex'][compressed.string] == pv.pubins.to_bytes(compressed=compressed.bool).hex()

    def test_pub_key_hash160(self, pv: pvobj, compressed):
        assert pv.json['pub']['hash160'][compressed.string] == pv.pubins.get_hash160(compressed=compressed.bool).hex()

    def test_pub_key_from_signed_message(self, message: msgobj):
        assert message.pv.pubins.key.to_string() == PublicKey.from_signed_message(message.json['sig'], message.json['string']).key.to_string()

    def test_pub_key_verify_message(self, message: msgobj):
        assert message.pv.pubins.verify_message(message.json['sig'], message.json['string'])

    def test_pub_key_verify_message_for_address(self, message: msgobj, address_type, network):
        assert message.pv.pubins.verify_message_for_address(
            message.json['sig'],
            message.json['string'],
            message.pv.pubins.get_address(address_type, network).string,
        )


class TestAddress:
    def test_script_pub_key(self, address: addrobj):
        assert address.json['script_pub_key'] == address.ins.script_pub_key.serialize().hex()

    def test_string(self, address: addrobj, network):
        ins = address.ins.change_network(network)
        assert ins.string == address.json['string'][network.value] == str(ins)

    def test_hash(self, address: addrobj):
        assert address.json['hash'] == address.ins.hash.hex()

    def test_network(self, address: addrobj):
        # start with 'mainnet' cause in address fixture ins init with "mainnet"
        assert address.ins.network == NetworkType.MAIN
        assert address.ins.change_network().network == NetworkType.TEST
