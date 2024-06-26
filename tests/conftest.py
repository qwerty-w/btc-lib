import json
from os import path
from functools import lru_cache
from dataclasses import dataclass
from typing import TypedDict, Literal

import pytest

from btclib.address import PrivateKey
from btclib.const import AddressType, NetworkType


type address_T = Literal[AddressType.P2PKH, AddressType.P2SH_P2WPKH, AddressType.P2WPKH, AddressType.P2WSH]


def pytest_addoption(parser: pytest.Parser):
    parser.addoption("--no-service", action="store", help='Exclude some services in test_service.py. '
                                                          'Supports recording as: "api1,api2" / "api1 api2" / "api1, api2"')


def pytest_configure(config: pytest.Config):
    for line in [
        'excluded: exclude test',
        'uncollect_if(*, func): function to unselect test from parametrization (mark all unselected test as "excluded")'
    ]:
        config.addinivalue_line('markers', line)


@pytest.hookimpl(hookwrapper=True)
def pytest_collectreport(report: pytest.CollectReport):
    """Handle "uncollect_if" and "excluded" marks for report items"""
    kept = []
    for item in report.result:
        if isinstance(item, pytest.Function):
            if item.get_closest_marker('excluded'):
                continue

            if m := item.get_closest_marker('uncollect_if'):
                func = m.kwargs['func']
                kwargs = item.callspec.params if hasattr(item, 'callspec') else {}
                try:
                    r = func(item, **kwargs)
                except TypeError as e:
                    raise TypeError('"uncollect_if" func and test func must '
                                    'have same parameterization arguments') from e
                if r:
                    item.add_marker('excluded')
                    continue
        kept.append(item)

    report.result[:] = kept
    yield


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]):
    """Handle "excluded" mark for tests items"""
    items[:] = filter(lambda x: not x.get_closest_marker('excluded'), items)


class _pv_detail_json(TypedDict):
    wif: dict[
        Literal['compressed', 'uncompressed'],
        dict[Literal['mainnet', 'testnet'], str]
    ]
    hex: str


class _pv_msgjson(TypedDict):
    string: str
    sig: str
    compressed: bool


class _pv_address_detail_json(TypedDict):
    string: dict[Literal['mainnet', 'testnet'], str]
    pkscript: str
    hash: str


class pvjson(TypedDict):
    pv: _pv_detail_json
    pub: dict[Literal['hex', 'hash160'], dict[Literal['compressed', 'uncompressed'], str]]
    messages: list[_pv_msgjson]
    P2PKH: _pv_address_detail_json
    P2SH_P2WPKH: _pv_address_detail_json
    P2WPKH: _pv_address_detail_json
    P2WSH: _pv_address_detail_json


class pvobj:
    with open(path.join(path.dirname(__file__), 'test_keys.json')) as __f:
        loaded: list[pvjson] = json.load(__f)

    def __init__(self, json: pvjson):
        self.json = json
        self.ins = PrivateKey.from_bytes(bytes.fromhex(json['pv']['hex']))
        self.pubins = self.ins.public

    @classmethod
    @lru_cache()
    def all(cls) -> list['pvobj']:
        return [cls(p) for p in cls.loaded]


@dataclass
class msgobj:
    json: _pv_msgjson
    pv: pvobj
    pvindex: int

    @classmethod
    @lru_cache
    def all(cls) -> list['msgobj']:
        return [cls(msg, p, i) for i, p in enumerate(pvobj.all()) for msg in p.json['messages']]


@dataclass
class addrobj:
    json: _pv_address_detail_json
    type: AddressType
    pv: pvobj

    def __post_init__(self) -> None:
        self.ins = self.pv.pubins.change_network(NetworkType.MAIN).get_address(self.type)


class iscompressed:
    def __init__(self, value: bool) -> None:
        self.string: Literal['compressed', 'uncompressed'] = 'compressed' if value else 'uncompressed'
        self.bool = value

    def __repr__(self) -> str:
        return self.string

    def __bool__(self) -> bool:
        return self.bool


@pytest.fixture(params=[NetworkType.MAIN, NetworkType.TEST], ids=lambda n: n.value)
def network(request) -> NetworkType:
    return request.param


@pytest.fixture(params=[iscompressed(True), iscompressed(False)], ids=lambda c: str(c))
def compressed(request) -> iscompressed:
    return request.param


@pytest.fixture(params=pvobj.all())
def pv(request) -> pvobj:
    return request.param


@pytest.fixture(params=msgobj.all(), ids=lambda msg: f'pv{msg.pvindex}-message')
def message(request) -> msgobj:
    return request.param


@pytest.fixture(
    params=[AddressType.P2PKH, AddressType.P2SH_P2WPKH, AddressType.P2WPKH, AddressType.P2WSH],
    ids=lambda at: at.value
)
def address_type(request) -> address_T:
    """
    :param request: The type of address "P2SH-P2WPKH" is written through a dash because PublicKey.get_address
                    is perceived only in this way.
                    When referring to a unit (GetterObject) itself will replace the dash with an underscore.
    """
    return request.param


@pytest.fixture
def address(pv: pvobj, address_type: address_T) -> addrobj:
    """
    Return prepared unit[address_type], add address instance.
    """
    return addrobj(pv.json[address_type.value], address_type, pv)
