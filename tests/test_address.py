import pytest
from .conftest import pvobj, addrobj, msgobj, address_T
from btclib.address import *


@pytest.fixture(params=['pub', 'hash', 'string', 'pkscript'])  # address instance from hash/pub/...etc
def address(request, pv: pvobj, address_type: address_T) -> addrobj:
    """
    It differs from the "address" fixture in conftest.py in that it has parameterization "from hash/pub/string/pkscript".
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


incorrect_addresses = [
    '0NL24E8oHWUGA8dbjQRnhhwEfzyo62E1fW',
    'L7eHfJVpaZjnkDJi5d8t487Tmpm1kQ3F8',
    'tl1qvdhxfplzc0xymvxm2an6zcy489jwqtaykynvgq',
    'gg1qljvsdavfjea3jhwvak2h2ht2kf9zpf39phhtyemv3d5n8r6vlspsjjcta8'
]


def test_getaddrinfo_correct_data(address: addrobj, network):
    t, n = getaddrinfo(address.json['string'][network.value])
    assert address.type == t
    assert network == n


@pytest.mark.parametrize('incorrect', incorrect_addresses)
def test_getaddrinfo_incorrect_data(incorrect):
    assert getaddrinfo(incorrect) == (None, None)


def test_validateaddr_correct_data(address: addrobj, network):
    s = address.json['string'][network.value]
    for t, n in [
        (address.type, network),
        (address.type, None),
        (None, network),
        (None, None)
    ]:
        assert validateaddr(s, t, n)


@pytest.mark.parametrize('incorrect', incorrect_addresses)
def test_validate_address_incorrect_data(incorrect, address_type, network):
    try:
        validateaddr(incorrect, address_type, network)
        assert False
    except (ValueError, AssertionError):
        assert True


@pytest.mark.parametrize('incorrect', incorrect_addresses)
def test_validate_address_incorrect_data_with_none_none(incorrect):
    try:
        validateaddr(incorrect, None, None)
        assert False
    except (ValueError, AssertionError):
        assert True

