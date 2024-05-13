import pytest
from requests import Session
from btclib import address
from btclib.const import NetworkType
from btclib.service import *


API_TIMEOUT = 30
API = type[BaseAPI]
transactions = [
    {
        'network': 'mainnet',
        'id': '3c44b04ea75904e0e48492b9de685b6a3c0923a4e35fa630b5558cf8a12840f2',
        'serialized': '02000000000101f002e438b459d97db0c5e75cb73640704d17ff6d5cbd86c39cf96b420e70da2b0100000000fdffffff0200000000000000000a6a5d0714c0a23314ce06b1ea000000000000160014c51b0d2bf1818f1c948159e74bcd992a64b8ef2102483045022100e4bc629d9d57de4a798f3b3fc7ba576285b231591fb3c24edc5f0790090de8130220734600f5341c929d1fa2a5dd781315cf1f3c35416a1da72db62d0e0b86852af501210372ad5541928a1c6459fce219a83ff4006ff7ee61163358ddaea61adf54cf703f00000000'
    }
]


@pytest.fixture(scope='session')
def session() -> requests.Session:
    return requests.Session()


@pytest.fixture(params=[BlockchairAPI, BlockstreamAPI, BlockchainAPI, BitcoreAPI])  # todo:  add BlockcypherAPI
def api(request: pytest.FixtureRequest) -> API:
    return request.param


@pytest.fixture(params=transactions)
def transaction(request: pytest.FixtureRequest) -> BroadcastedTransaction:
    request.param['network'] = NetworkType(request.param['network'])
    return request.param


def uncollect_apis(get_network_f: typing.Callable[[dict[str, typing.Any]], str | NetworkType]):
    """Exclude api if method not implemented or api doesn't support network"""
    def inner(item: pytest.Function, api: API, **kwargs):
        method = item.originalname.replace('test_', '')
        assert hasattr(api, method), 'uncollect_apis requires function with name like in BaseAPI methods: test_<name> == BaseAPI.<name>'

        network = get_network_f(kwargs)
        return not api.supports_network(NetworkType(network) if isinstance(network, str) else network) or 'BaseAPI' in getattr(api, method).__qualname__

    return inner


class TestAPIs:
    @pytest.mark.uncollect_if(func=uncollect_apis(lambda k: k['transaction']['network']))
    def test_get_transaction(self, session: Session, api: API, transaction: dict[str, typing.Any]):
        tx = api(session, transaction['network'], timeout=API_TIMEOUT).get_transaction(transaction['id'])
        assert tx.serialize().hex() == transaction['serialized']

    @pytest.mark.uncollect_if(func=uncollect_apis(lambda k: k['transaction']['network']))
    def test_get_transactions(self, session: Session, api: API, transaction: dict[str, typing.Any]):
        txs = api(session, transaction['network'], timeout=API_TIMEOUT).get_transactions([transaction['id']])
        assert all(map(lambda tx: tx.serialize().hex() == transaction['serialized'], txs))

    @pytest.mark.parametrize('address, network', [
        (address.P2WPKH('bc1q7wn3nmhnvsr0q2gg8nnntga9u93ycl3nj6nf0h'), NetworkType.MAIN),
        (address.P2SH('2N1rjhumXA3ephUQTDMfGhufxGQPZuZUTMk'), NetworkType.TEST)
    ])
    @pytest.mark.uncollect_if(func=uncollect_apis(lambda k: k['network']))
    def test_get_address_transactions(self, session: Session, address: Address, network: NetworkType, api: API):
        f = api(session, network, timeout=API_TIMEOUT).get_address_transactions
        k = {'length': 10} if 'length' in f.__code__.co_varnames else {}
        txs = f(address, **k)
        assert len(txs) > 0
        assert all(isinstance(tx, BroadcastedTransaction) for tx in txs)

    @pytest.mark.uncollect_if(func=uncollect_apis(lambda k: k['network']))
    def test_head(self, session: Session, network: NetworkType, api: API):
        if api is not BlockchainAPI or network is NetworkType.MAIN:
            return
        h = api(session, network).head()
        assert not h.is_mempool()
        assert h > { NetworkType.MAIN: 840000, NetworkType.TEST: 2800000 }[network]  # last halving
