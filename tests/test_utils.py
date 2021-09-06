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


@pytest.fixture(params=[sint32, sint64])
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
    # def test_size(self, cls):
    #     assert int(cls.__name__[-2:]) == cls.size * 8
    #
    # @pytest.mark.parametrize('level', ['max', 'min'])
    # def test_min_max_size(self, int_cls, level):
    #     value = int_ranges[int_cls._signed][int_cls.size * 8][0 if level == 'min' else 1]
    #
    #     try:
    #         int_cls(value)
    #     except:
    #         assert False
    #
    #     try:
    #         int_cls(value + (-1 if level == 'min' else 1))
    #         assert False
    #     except:
    #         assert True

    def test_pack(self, randint, byteorder):
        integer, int_cls = randint.int, randint.cls
        assert int_cls(integer).pack(byteorder) == integer.to_bytes(int_cls.size, byteorder, signed=int_cls._signed)

    def test_unpack(self, randint, byteorder):
        integer, int_cls = randint.int, randint.cls
        assert integer == int_cls.unpack(integer.to_bytes(int_cls.size, byteorder, signed=int_cls._signed), byteorder)


def test_get_2sha256():
    random_data = random.randbytes(64)
    assert sha256(sha256(random_data).digest()).digest() == get_2sha256(random_data)
