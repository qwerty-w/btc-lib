import pytest
from addresses import *


@pytest.fixture(params=['hash', 'pub'])  # address instance from hash/pub
def address(request, unit, address_type):
    """
    It differs from the "address" fixture in conftest.py in that it has parameterization "from hash / pub".
    Has the same name for convenience.
    """
    address = unit[address_type]
    address_instance = unit.pub.instance.get_address(address_type, 'mainnet')

    if request.param == 'hash':
        address_instance = type(address_instance).from_hash(address.hash)

    address.set_data({'instance': address_instance})
    return address


class TestPrivatePublicKey:
    def test_private_key_creation(self, unit, compressed, network):  # test PrivateKey._from_wif
        instance = PrivateKey(unit.pv.wif[compressed.string][network])

        assert instance.to_bytes() == unit.pv.bytes

    def test_private_key_to_wif(self, unit, compressed, network):
        wif = unit.pv.wif[compressed.string][network]
        instance = PrivateKey(wif)

        assert instance.to_wif(network, compressed=compressed.bool) == wif

    def test_private_key_sign_message(self, message):
        assert message.unit.pv.instance.sign_message(message.string) == message.sig

    def test_pub_key_from_signed_message(self, message):
        assert PublicKey.from_signed_message(message.sig, message.string).bytes == message.unit.pub.bytes

    def test_pub_key_verify_message(self, message):
        assert message.unit.pub.instance.verify_message(message.sig, message.string)

    def test_pub_key_verify_message_for_address(self, message, address_type, network):
        assert message.unit.pub.instance.verify_message_for_address(
            message.sig,
            message.string,
            message.unit.pub.instance.get_address(address_type, network).string,
        )

    def test_pub_key_creation(self, unit):
        assert unit.pub.instance.bytes == unit.pub.bytes

    def test_pub_key_to_hex(self, unit, compressed):
        assert unit.pub.instance.to_hex(compressed=compressed.bool) == unit.pub.hex[compressed.string]

    def test_pub_key_hash160(self, unit, compressed):
        assert unit.pub.instance.get_hash160(compressed=compressed.bool) == unit.pub.hash160[compressed.string]


class TestAddresses:
    def test_script_pub_key(self, address):
        assert address.instance.script_pub_key.to_hex() == address.script_pub_key

    def test_string(self, address, network):
        ins = address.instance.change_network(network)
        assert ins.string == address.string[network] == str(ins)

    def test_hash(self, address):
        assert address.instance.hash == address.hash

    def test_network(self, address):
        # 'mainnet' because in address fixture instance init with "mainnet" network arg
        assert address.instance.network == 'mainnet'
