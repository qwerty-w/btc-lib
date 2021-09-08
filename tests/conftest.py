from __future__ import annotations
import typing
import json
import pytest

from addresses import PrivateKey


class GetterObject:
    def __init__(self, data: dict):
        self._cached_object_attrs = []
        self._deep_setter(data)

    def _deep_setter(self, obj: dict):
        for name, value in obj.items():
            name = self._prepare_name(name)
            setattr(self, name, value if not isinstance(value, dict) else GetterObject(value))
            self._cached_object_attrs.append(name)

    @staticmethod
    def _prepare_name(name: str) -> str:
        return name.replace('-', '_')

    def __getitem__(self, item) -> GetterObject | str | bytes | typing.Any:
        name = self._prepare_name(item)
        return getattr(self, name)

    def __repr__(self):
        return f'{self.__class__.__name__}({", ".join(sorted(self.get_attrs(), key=str.isupper))})'

    def set_data(self, data: dict):
        self._deep_setter(data)

    def get_attrs(self) -> list:
        return self._cached_object_attrs.copy()

    def get_raw(self) -> dict:
        attrs = self.get_attrs()

        data = []
        for attr_str in attrs:
            attr = getattr(self, attr_str)
            data.append((attr_str, attr if not isinstance(attr, GetterObject) else attr.get_raw()))

        return dict(data)

    def copy(self) -> GetterObject:
        return type(self)(self.get_raw())


class Unit(GetterObject):
    __slots__ = ('pv', 'pub', 'P2PKH', 'P2SH_P2WPKH', 'P2WPKH', 'P2WSH')


def get_units(path: str) -> list:
    with open(path) as f:
        units = json.load(f)

    for unit in units:
        unit['pv']['bytes'] = bytes.fromhex(unit['pv']['hex'])
        unit['pub']['bytes'] = bytes.fromhex(unit['pub']['hex']['uncompressed'][2:])

    return [Unit(unit_data) for unit_data in units]


class IsCompressed:
    def __init__(self, value: bool):
        self.string = 'compressed' if value else 'uncompressed'
        self.bool = value


@pytest.fixture(params=['mainnet', 'testnet'])
def network(request) -> str:
    return request.param


@pytest.fixture(params=[IsCompressed(True), IsCompressed(False)])
def compressed(request) -> IsCompressed:
    return request.param


@pytest.fixture(params=get_units('address_units.json'))
def unit(request):
    """
    Prepare unit, add pv and pub instances.
    """
    unit = request.param
    data = {'pv': (pv := PrivateKey(unit.pv.wif.compressed.mainnet)), 'pub': pv.pub}

    for name, instance in data.items():
        unit[name].set_data({'instance': instance})

    return unit


def at_id(name):
    return f'<{name}>'


@pytest.fixture(params=['P2PKH', 'P2SH-P2WPKH', 'P2WPKH', 'P2WSH'], ids=at_id)
def address_type(request) -> str:
    """
    :param request: The type of address "P2SH-P2WPKH" is written through a dash because PublicKey.get_address
                    is perceived only in this way.
                    When referring to a unit (GetterObject) itself will replace the dash with an underscore.
    :return:
    """
    return request.param


@pytest.fixture
def address(unit, address_type):
    """
    Return prepared unit[address_type], add address instance.
    """
    address = unit[address_type]
    address_instance = unit.pub.instance.get_address(address_type, 'mainnet')
    address.set_data({'instance': address_instance})
    return address
