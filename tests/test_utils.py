import random
from collections import namedtuple
import pytest

from btclib.utils import *


randint_d = namedtuple('RandIntData', 'int cls')
int_ranges = {
    'signed': {
        32: [-2147483648, 2147483647],
        64: [-9223372036854775808, 9223372036854775807]
    },
    'unsigned': {
        32: [0, 4294967295],
        64: [0, 18446744073709551615]
    }
}

i2b_data = [
    (-32767, b'\x80\x01'),
    (-32768, b'\x80\x00'),
    (-32769, b'\xff\x7f\xff'),
    (-127, b'\x81'),
    (-128, b'\x80'),
    (-129, b'\xff\x7f'),
    (127, b'\x7f'),
    (128, b'\x00\x80'),
    (32767, b'\x7f\xff'),
    (32768, b'\x00\x80\x00'),

    (10000000, b'\x00\x98\x96\x80'),
    (-10000000, b'\xff\x67\x69\x80')
]

incorrect_addresses = [
    '0NL24E8oHWUGA8dbjQRnhhwEfzyo62E1fW',
    'L7eHfJVpaZjnkDJi5d8t487Tmpm1kQ3F8',
    'tl1qvdhxfplzc0xymvxm2an6zcy489jwqtaykynvgq',
    'gg1qljvsdavfjea3jhwvak2h2ht2kf9zpf39phhtyemv3d5n8r6vlspsjjcta8'
]


@pytest.fixture(params=[sint32, sint64, uint32, uint64])
def int_cls(request):
    return request.param


@pytest.fixture
def randint(int_cls):
    min_, max_ = int_ranges['signed' if int_cls._signed else 'unsigned'][int_cls.size * 8]
    randint = random.randint(min_, max_)
    return randint_d(randint, int_cls)


@pytest.fixture(params=['little', 'big'])
def byteorder(request):
    return request.param


@pytest.fixture(params=['min', 'max'])
def level(request):
    return request.param


class IsIncreased:
    def __init__(self, value: bool):
        self.string = 'increased' if value else 'default'
        self.bool = value


def _test_min_max_size(cls, values, level):
    value = values[0 if level == 'min' else 1]

    # cls(max/min_value) - should be pass
    try:
        cls(value)
    except:
        return False

    # cls(max + 1/min - 1 value) - should be not pass
    try:
        cls(value + (-1 if level == 'min' else 1))
    except:
        return True

    return False


class TestUnsignedInt:
    def test_size(self, int_cls):
        assert int(int_cls.__name__[-2:]) == int_cls.size * 8

    def test_min_max_size(self, int_cls, level):
        assert _test_min_max_size(
            int_cls,
            int_ranges['signed' if int_cls._signed else 'unsigned'][int_cls.size * 8],
            level
        )

    def test_pack(self, randint, byteorder):
        integer, int_cls = randint.int, randint.cls
        assert int_cls(integer).pack(byteorder) == integer.to_bytes(int_cls.size, byteorder, signed=int_cls._signed)

    def test_unpack(self, randint, byteorder):
        integer, int_cls = randint.int, randint.cls
        assert integer == int_cls.unpack(integer.to_bytes(int_cls.size, byteorder, signed=int_cls._signed), byteorder)


def inc_id(item):
    return item.string


@pytest.fixture(params=[IsIncreased(True), IsIncreased(False)], ids=inc_id)
def increased(request):
    return request.param


class TestDynamicInt:
    def test_min_max_size(self, level, increased):
        assert _test_min_max_size(
            lambda v: dint(v).pack(increased_separator=increased.bool),
            int_ranges['unsigned'][64 if increased.bool else 32],
            level
        )

    @staticmethod
    def _bsize_gen(increased, byteorder):  # iterate all possible sizes with random int
        index = 2  # start with 2 bytes size

        for sep, max_size in SEPARATORS[increased.string].items():
            for bsize in range(index, max_size + 1):
                int_b = random.randbytes(bsize)
                # fill with b'\x00' to max_size
                int_b = b''.join(b'\x00' for _ in range(max_size - bsize)) + int_b
                int_b = int_b[::-1 if byteorder == 'little' else 1]

                yield sep, int_b

            index = max_size + 1

    @staticmethod
    def _one_bsize_gen(sep_start, increased, byteorder):
        for integer in range(sep_start, 256):
            sep = SEPARATORS_REVERSED[increased.string][2 if increased.bool else 1]
            int_b = ((b'\x00' if increased.bool else b'') + bytes([integer]))[::-1 if byteorder == 'little' else 1]
            yield sep, int_b

    def test_pack_one_bsize_separator(self, byteorder, increased):
        separators_start = 76 if not increased.bool else 253

        for integer in range(separators_start):
            assert dint(integer).pack(byteorder, increased_separator=increased.bool) == bytes([integer])

        for sep, int_b in self._one_bsize_gen(separators_start, increased, byteorder):
            packed = dint(int.from_bytes(int_b, byteorder)).pack(byteorder, increased_separator=increased.bool)
            assert sep + int_b == packed

    def test_pack_separators(self, increased, byteorder):
        for sep, int_b in self._bsize_gen(increased, byteorder):
            packed = dint(int.from_bytes(int_b, byteorder)).pack(byteorder, increased_separator=increased.bool)

            assert sep + int_b == packed

    def test_unpack_one_bsize_separator(self, increased, byteorder):
        separators_start = 76 if not increased.bool else 253

        for integer in range(separators_start):
            assert dint.unpack(bytes([integer]), byteorder, increased_separator=increased.bool)[0] == integer

        for sep, int_b in self._one_bsize_gen(separators_start, increased, byteorder):
            unpacked = dint.unpack(sep + int_b, byteorder, increased_separator=increased.bool)[0]
            assert int.from_bytes(int_b, byteorder) == unpacked

    def test_unpack_separators(self, increased, byteorder):
        for sep, int_b in self._bsize_gen(increased, byteorder):
            out_int, _ = dint.unpack(
                sep + int_b,
                byteorder,
                increased_separator=increased.bool
            )
            assert out_int == int.from_bytes(int_b, byteorder)


@pytest.mark.repeat(10)
def test_d_sha256():
    random_data = random.randbytes(64)
    assert sha256(sha256(random_data).digest()).digest() == d_sha256(random_data)


def i2b_id(data):
    integer, integer_bytes = data
    return f'<{integer}>-0x{integer_bytes.hex()}'


@pytest.fixture(params=i2b_data, ids=i2b_id)
def i2b_items(request, byteorder):
    integer, integer_bytes = request.param
    return (integer, integer_bytes if byteorder == 'big' else integer_bytes[::-1]), byteorder


def test_int2bytes_signed(i2b_items):
    (integer, integer_bytes), byteorder = i2b_items
    assert integer_bytes == int2bytes(integer, byteorder, signed=True)


def test_bytes2int_signed(i2b_items):
    (integer, integer_bytes), byteorder = i2b_items
    assert integer == bytes2int(integer_bytes, byteorder, signed=True)


def test_get_address_network_correct_data(address, network):
    assert network == get_address_network(address.string[network])


@pytest.mark.parametrize('incorrect_address', incorrect_addresses)
def test_get_address_network_incorrect_data(incorrect_address):
    assert get_address_network(incorrect_address) is None


def test_get_address_type(address, network):
    assert get_address_type(address.string[network]) == address.instance.type


def test_validate_address_correct_data(address, network):
    assert validate_address(address.string[network], address.instance.type, network)


@pytest.mark.parametrize('incorrect_address', incorrect_addresses)
def test_validate_address_incorrect_data(incorrect_address):
    assert False is validate_address(
        incorrect_address,
        random.choice(['P2PKH', 'P2SH', 'P2WSH', 'P2WPKH']),
        random.choice(['mainnet', 'testnet'])
    )
