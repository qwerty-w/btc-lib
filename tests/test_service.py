from typing import Optional

import pytest
from httpx import Client

from btclib import address
from btclib.const import NetworkType
from btclib.service import *


API_TIMEOUT = 30
API = type[ExplorerAPI]
transactions = [
    {
        # no sigscript
        'network': 'mainnet',
        'id': '3c44b04ea75904e0e48492b9de685b6a3c0923a4e35fa630b5558cf8a12840f2',
        'serialized': '02000000000101f002e438b459d97db0c5e75cb73640704d17ff6d5cbd86c39cf96b420e70da2b0100000000fdffffff0200000000000000000a6a5d0714c0a23314ce06b1ea000000000000160014c51b0d2bf1818f1c948159e74bcd992a64b8ef2102483045022100e4bc629d9d57de4a798f3b3fc7ba576285b231591fb3c24edc5f0790090de8130220734600f5341c929d1fa2a5dd781315cf1f3c35416a1da72db62d0e0b86852af501210372ad5541928a1c6459fce219a83ff4006ff7ee61163358ddaea61adf54cf703f00000000'
    },
    {
        # no witness
        'network': 'mainnet',
        'id': '7a1b743fe94e83edbe458ea5d8ebcba6b041180908121b118bd03e1843198b7b',
        'serialized': '02000000013f577895d204f5f3f5381143711d67c2f54703fa5e57e84ae553160e7f7eece4000000006a47304402204c3a105ce7c5c4822a6c74b581eebb81c101a40dc52459f935ace5ffe72f964e022010f4a03e6605b015491458556d7d94f617f60cb863a6badae26141ce09f27c09012103e1a63aaaba2067ff69ead8c13de230c39cac91c6802a154f91f07f741fe85e3cfdffffff01293c4f000000000017a9140444033b56d5e3d288303388fc0d19da82bcf8f68700000000'
    }
]
coinbase_transactions = [
    {
        # genesis
        'network': 'mainnet',
        'id': '4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b',
        'height': -1,  # 0
        'serialized': '01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff4d04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73ffffffff0100f2052a01000000434104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac00000000'
    },
    {
        'network': 'mainnet',
        'id': 'cbbcbf0d1c88924c7f01efc52b66e72f5c73e58f989d4ffe4cacd6b5b33badf3',
        'height': 847217,
        'serialized': '010000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff580371ed0c1b4d696e656420627920416e74506f6f6c393730b9001e03207cf8fbfabe6d6d33451c7b6d84e5fd372b8505c1231a14801e58c045907e96419986b9482e987e10000000000000000000c1083829000000000000ffffffff05220200000000000017a91442402a28dd61f2718a4b27ae72a4791d5bbdade787ae5e25140000000017a9145249bdf2c131d43995cff42e8feee293f79297a8870000000000000000266a24aa21a9ed047798dde48c2de8536b9f02b14a68a1e7126baeb6de8143adbff38fdabc353a00000000000000002f6a2d434f5245012953559db5cc88ab20b1960faa9793803d0703374e3ecda72cb7961caa4b541b1e322bcfe0b5a03000000000000000002b6a2952534b424c4f434b3ae8d041e1a63c098a27e92839dbc993a3ff66df8dc4d99d09b3575e220061f62a0120000000000000000000000000000000000000000000000000000000000000000000000000'
    }
]


def handle_noservice(request: pytest.FixtureRequest, pytestconfig: pytest.Config):
    no_service: str = pytestconfig.getoption('--no-service', default=None)  # type: ignore
    if no_service:
        no_service = no_service.strip()

        for sep in [', ', ',', ' ']:
            if sep in no_service:
                names = no_service.split(sep)
                break
        else:
            names = [no_service]

        if request.param.__name__ in names:
            pytest.skip('cause in --no-service')


@pytest.fixture(scope='session')
def client() -> Client:
    return Client(follow_redirects=True)


@pytest.fixture(params=[BlockstreamAPI, BlockchairAPI, BlockchainAPI, BitcoreAPI])  # todo:  add BlockcypherAPI
def api(request: pytest.FixtureRequest, pytestconfig: pytest.Config) -> API:
    handle_noservice(request, pytestconfig)
    return request.param


@pytest.fixture(params=transactions)
def transaction(request: pytest.FixtureRequest) -> BroadcastedTransaction:
    request.param['network'] = NetworkType(request.param['network'])
    return request.param


@pytest.fixture(params=coinbase_transactions)
def coinbase_tx(request: pytest.FixtureRequest) -> BroadcastedTransaction:
    request.param['network'] = NetworkType(request.param['network'])
    return request.param


def uncollect_apis(get_network_f: typing.Callable[[dict[str, typing.Any]], str | NetworkType],
                   method_name: Optional[str] = None):
    """Exclude api if method not implemented or api doesn't support network"""
    def inner(item: pytest.Function, api: API, **kwargs):
        method = method_name or item.originalname.replace('test_', '')
        assert hasattr(api, method), 'uncollect_apis requires function with name like in ExplorerAPI methods: test_<name> == ExplorerAPI.<name> or set method_name'

        network = get_network_f(kwargs)
        return not api.supports_network(NetworkType(network) if isinstance(network, str) else network) or 'ExplorerAPI' in getattr(api, method).__qualname__

    return inner


@pytest.fixture(params=[
    (address.P2WPKH.from_string('bc1q7wn3nmhnvsr0q2gg8nnntga9u93ycl3nj6nf0h'), NetworkType.MAIN),
    (address.P2SH.from_string('2N1rjhumXA3ephUQTDMfGhufxGQPZuZUTMk'), NetworkType.TEST)
])
def addr(request: pytest.FixtureRequest) -> tuple[BaseAddress, NetworkType]:
    return request.param


class TestExplorerAPIs:
    @pytest.mark.uncollect_if(func=uncollect_apis(lambda k: k['addr'][1]))
    def test_get_address(self, client: Client, api: API, addr: tuple[BaseAddress, NetworkType]):
        address, network = addr
        inf = api(network, client, timeout=API_TIMEOUT).get_address(address)
        assert isinstance(inf, AddressInfo)
        assert all(isinstance(x, int) for x in [inf.received, inf.balance, inf.spent, inf.tx_count])

    @pytest.mark.uncollect_if(func=uncollect_apis(lambda k: k['transaction']['network']))
    def test_get_transaction(self, client: Client, api: API, transaction: dict[str, typing.Any]):
        tx = api(transaction['network'], client, timeout=API_TIMEOUT).get_transaction(transaction['id'])
        assert tx.serialize().hex() == transaction['serialized']

    @pytest.mark.uncollect_if(func=uncollect_apis(lambda k: k['transaction']['network']))
    def test_get_transactions(self, client: Client, api: API, transaction: dict[str, typing.Any]):
        txs = api(transaction['network'], client, timeout=API_TIMEOUT).get_transactions([transaction['id']])
        assert all(map(lambda tx: tx.serialize().hex() == transaction['serialized'], txs))

    @pytest.mark.uncollect_if(func=uncollect_apis(lambda k: k['addr'][1]))
    def test_get_address_transactions(self, client: Client, api: API, addr: tuple[BaseAddress, NetworkType]):
        address, network = addr
        f = api(network, client, timeout=API_TIMEOUT).get_address_transactions
        k = {'length': 10} if 'length' in f.__code__.co_varnames else {}
        txs = f(address, **k)
        assert len(txs) > 0
        assert all(isinstance(tx, BroadcastedTransaction) for tx in txs)

    @pytest.mark.uncollect_if(func=uncollect_apis(lambda k: k['addr'][1]))
    def test_get_unspent(self, client: Client, api: API, addr: tuple[BaseAddress, NetworkType]):
        address, network = addr
        un = api(network, client, timeout=API_TIMEOUT).get_unspent(address)
        assert all(isinstance(u, Unspent) for u in un)
        assert all(u.txid.hex() for u in un)

    @pytest.mark.uncollect_if(func=uncollect_apis(lambda k: k['network']))
    def test_head(self, client: Client, network: NetworkType, api: API):
        if api is not BlockchainAPI or network is NetworkType.MAIN:
            return
        h = api(network, client, timeout=API_TIMEOUT).head()
        assert not h.is_mempool()
        assert h > { NetworkType.MAIN: 840000, NetworkType.TEST: 2800000 }[network]  # last halving

    @pytest.mark.uncollect_if(func=uncollect_apis(lambda k: k['coinbase_tx']['network'], 'get_transaction'))
    def test_coinbase_transactions(self, client: Client, api: API, coinbase_tx: dict[str, typing.Any]):
        tx = api(coinbase_tx['network'], client, timeout=API_TIMEOUT).get_transaction(coinbase_tx['id'])
        assert tx.is_coinbase()
        if api is not BlockchairAPI:
            if coinbase_tx['height'] != -1:
                assert tx.inputs[0].parse_height() == coinbase_tx['height']   # type: ignore fixme: tx.inputs[0] type ?
            assert tx.serialize().hex() == coinbase_tx['serialized']


@pytest.fixture(scope='module', params=[BitcoinFeesAPI, MempoolSpaceAPI])
def rateapi(request: pytest.FixtureRequest, pytestconfig: pytest.Config, client: Client):
    handle_noservice(request, pytestconfig)
    a = request.param(NetworkType.MAIN, client, timeout=API_TIMEOUT)
    return a, a.get_rate()


class TestFeeRateAPIs:
    def tfeerateattrs(self, r: FeeRate):
        for v in [
            r.next,
            r.halfhour,
            r.hour,
            r.low,
            r.minimum
        ]:
            assert isinstance(v, int)
            assert v > 0

    def test_get_rate(self, rateapi: tuple[FeeRateAPI, FeeRate]):
        a, r = rateapi
        assert isinstance(r, FeeRate)
        self.tfeerateattrs(r)

    @pytest.mark.parametrize('vsize', [188, 10, 200, 249, 1203, 5, 800])
    def test_calcfee(self, vsize: int, rateapi: tuple[FeeRateAPI, FeeRate]):
        a, r = rateapi
        cr = a.calcfee(vsize, r)
        assert isinstance(cr, FeeRate)
        self.tfeerateattrs(cr)
