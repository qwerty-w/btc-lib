from os import path
from typing import Any
import json
import pytest

from btclib.address import PrivateKey
from btclib.utils import pprint_class
from btclib.const import AddressType, NetworkType


class TestData:
    UNITS_FP = path.join(path.dirname(__file__), 'address_units.json')
    _units = []
    _messages = []

    @classmethod
    @property
    def units(cls) -> list:
        cls._units = cls._units if len(cls._units) > 0 else cls.get_units()
        return cls._units

    @classmethod
    @property
    def messages(cls) -> list:
        cls._messages = cls._messages if len(cls._messages) > 0 else cls.get_messages()
        return cls._messages

    @classmethod
    def get_units(cls) -> list:
        with open(cls.UNITS_FP) as f:
            units = json.load(f)

        for unit in units:
            unit['pv']['bytes'] = bytes.fromhex(unit['pv']['hex'])
            unit['pub']['bytes'] = bytes.fromhex(unit['pub']['hex']['compressed'])

        return [Unit(unit_data) for unit_data in units]

    @classmethod
    def get_messages(cls) -> list:
        messages = []

        for unit_index, unit in enumerate(cls.units):
            if not getattr(unit, 'messages', False):
                continue

            for message in unit.messages:
                message.set_data({'unit_index': unit_index})
                messages.append(message)

        return messages

    @classmethod
    def prepare_unit(cls, unit: 'Unit'):  # prepare unit, add instances
        unit = unit.copy()
        data = {'pv': (pv := PrivateKey.from_wif(unit.pv.wif.compressed['mainnet'])), 'pub': pv.public}

        for name, instance in data.items():
            unit[name].set_data({'instance': instance})

        return unit

    @classmethod
    def prepare_message(cls, message: 'GetterObject'):  # prepare message, add unit
        message = message.copy()
        message.set_data({
            'unit': cls.prepare_unit(cls.units[message.unit_index]).copy()
        })
        return message


class GetterObject:
    def __init__(self, data: dict):
        self._cached_object_attrs = []
        self._setter(data)

    def _handler(self, obj):
        if not isinstance(obj, (dict, list)):
            return obj

        if isinstance(obj, dict):
            return GetterObject(obj)

        items = []
        for item in obj:
            items.append(self._handler(item))

        return items

    def _setter(self, data: dict):
        for name, value in data.items():
            name = self._prepare_name(name)
            setattr(self, name, self._handler(value))
            self._cached_object_attrs.append(name)

    @staticmethod
    def _prepare_name(name: str) -> str:
        return name.replace('-', '_')

    def __getitem__(self, item) -> 'GetterObject | str | bytes | Any':
        name = self._prepare_name(item)
        return getattr(self, name)

    def __repr__(self):
        return pprint_class(self, sorted(self.get_attrs(), key=str.isupper))

    def copy(self) -> 'GetterObject':
        return type(self)(self.get_raw())

    def get_attrs(self) -> list:
        return self._cached_object_attrs.copy()

    def get_raw(self) -> dict:
        attrs = self.get_attrs()

        data = []
        for attr_str in attrs:
            attr = getattr(self, attr_str)
            data.append((attr_str, attr if not isinstance(attr, GetterObject) else attr.get_raw()))

        return dict(data)

    def set_data(self, data: dict):
        self._setter(data)

    def pop_attr(self, attr_name: str):
        value = getattr(self, attr_name)
        delattr(self, attr_name)
        return value


class Unit(GetterObject):
    __slots__ = ('pv', 'pub', 'P2PKH', 'P2SH_P2WPKH', 'P2WPKH', 'P2WSH')


class IsCompressed:
    def __init__(self, value: bool):
        self.string = 'compressed' if value else 'uncompressed'
        self.bool = value


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


@pytest.fixture(params=[NetworkType.MAIN, NetworkType.TEST])
def network(request) -> NetworkType:
    return request.param


@pytest.fixture(params=[IsCompressed(True), IsCompressed(False)])
def compressed(request) -> IsCompressed:
    return request.param


@pytest.fixture(params=TestData.units)
def unit(request):
    return TestData.prepare_unit(request.param)


def msg_id(message):
    return f'unit{message.unit_index}-message'


@pytest.fixture(params=TestData.messages, ids=msg_id)
def message(request):
    return TestData.prepare_message(request.param)


def at_id(address_type):
    return f'<{address_type}>'


@pytest.fixture(params=[AddressType.P2PKH, AddressType.P2SH_P2WPKH, AddressType.P2WPKH, AddressType.P2WSH], ids=at_id)
def address_type(request) -> AddressType:
    """
    :param request: The type of address "P2SH-P2WPKH" is written through a dash because PublicKey.get_address
                    is perceived only in this way.
                    When referring to a unit (GetterObject) itself will replace the dash with an underscore.
    """
    return request.param


@pytest.fixture
def address(unit, address_type):
    """
    Return prepared unit[address_type], add address instance.
    """
    address = unit[address_type.value.replace('_', '-')]
    address_instance = unit.pub.instance.get_address(address_type, NetworkType.MAIN)
    address.set_data({'instance': address_instance})
    return address
