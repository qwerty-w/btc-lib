import random
from collections import namedtuple
import pytest
from utils import *


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


class TestUnsignedInt:
    def test_size(self, int_cls):
        assert int(int_cls.__name__[-2:]) == int_cls.size * 8

    @pytest.mark.parametrize('level', ['max', 'min'])
    def test_min_max_size(self, int_cls, level):
        signed = 'signed' if int_cls._signed else 'unsigned'
        level_value = int_ranges[signed][int_cls.size * 8][0 if level == 'min' else 1]

        # cls(max/min_value) - should be pass
        try:
            int_cls(level_value)
        except:
            assert False

        # cls(max + 1/min - 1 value) - should be not pass
        try:
            int_cls(level_value + (-1 if level == 'min' else 1))
            assert False
        except:
            assert True

    def test_pack(self, randint, byteorder):
        integer, int_cls = randint.int, randint.cls
        assert int_cls(integer).pack(byteorder) == integer.to_bytes(int_cls.size, byteorder, signed=int_cls._signed)

    def test_unpack(self, randint, byteorder):
        integer, int_cls = randint.int, randint.cls
        assert integer == int_cls.unpack(integer.to_bytes(int_cls.size, byteorder, signed=int_cls._signed), byteorder)


@pytest.mark.repeat(10)
def test_get_2sha256():
    random_data = random.randbytes(64)
    assert sha256(sha256(random_data).digest()).digest() == get_2sha256(random_data)


def i2b_id(data):
    integer, integer_bytes = data
    return f'({integer})-0x{integer_bytes.hex()}'


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
