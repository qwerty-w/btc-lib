import typing
from abc import ABC, abstractmethod
from dataclasses import dataclass
import requests

from btclib.script import Script
from btclib.address import BaseAddress, PrivateKey
from btclib.const import NetworkType, DEFAULT_NETWORK, DEFAULT_SERVICE_TIMEOUT
from btclib.transaction import Block, CoinbaseInput, Unspent, RawTransaction, Transaction, BroadcastedTransaction, ioList, UnsignableInput, Input, Output


@dataclass
class ServiceError(Exception):
    message: str
    attr: str
    priority: 'Service._api_priority_T'
    errors: dict['BaseAPI', 'Exception']

    def __str__(self) -> str:
        return self.message

@dataclass
class NetworkError(Exception):
    api: 'BaseAPI'
    response: requests.Response

    def __post_init__(self) -> None:
        self.status_code: int = self.response.status_code
        self.request: requests.PreparedRequest = self.response.request

    def __str__(self) -> str:
        return f'{self.api.__class__.__name__} {self.status_code} {self.request.url}'


# exceptions
class ExceededLimitError(NetworkError):...
class NotFoundError(NetworkError, LookupError): ...
class ExcessiveAddress(NetworkError, OverflowError): ...
class ServiceUnavailableError(NetworkError): ...
class AddressOverflowError(NetworkError, OverflowError): ...


@dataclass
class AddressInfo:
    received: int
    spent: int
    tx_count: int
    address: BaseAddress

    def __post_init__(self) -> None:
        self.balance: int = self.received - self.spent


class BaseAPI(ABC):
    uri: dict[NetworkType, str] = NotImplemented
    endpoints: dict[str, str] = NotImplemented

    _unsupported_network_error = lambda s, n: TypeError(f'{s.__class__.__name__} doesn\'t support {n.value} network')

    def __init__(self,
                 network: NetworkType = DEFAULT_NETWORK,
                 session: typing.Optional[requests.Session] = None,
                 timeout: int = DEFAULT_SERVICE_TIMEOUT) -> None:
        self.session = session or requests.Session()
        self.network = network
        self.timeout = timeout

        if not self.supports_network(network):
            raise self._unsupported_network_error(network)

    @classmethod
    def supports_network(cls, network: NetworkType) -> bool:
        return network in cls.uri

    def toggle_network(self, network: typing.Optional[NetworkType] = None) -> None:
        if network == self.network:
            return
        if not network:
            network = self.network.toggle()
        if not self.supports_network(network):
            raise self._unsupported_network_error(network)

        self.network = network

    def get_endpoint(self, key: str, **kwargs) -> str:
        return self.endpoints[key].format(uri=self.uri[self.network], **kwargs)

    def request(self,
                method: str,
                endpoint_key: str,
                session_params: dict[str, typing.Any] = {},
                *,
                handle_response: bool = True, **kwargs) -> requests.Response:
        session_params.setdefault('timeout', self.timeout)
        r = self.session.request(method, self.get_endpoint(endpoint_key, **kwargs), **session_params)
        if handle_response:
            self.handle_response(r)
        return r

    def get(self,
            endpoint_key: str,
            session_params: dict[str, typing.Any] = {},
            *,
            handle_response: bool = True,
            **kwargs) -> requests.Response:
        return self.request('GET', endpoint_key, session_params, handle_response=handle_response, **kwargs)

    def post(self,
             endpoint_key: str,
             session_params: dict[str, typing.Any] = {},
             *,
             handle_response: bool = True,
             **kwargs) -> requests.Response:
        return self.request('POST', endpoint_key, session_params, handle_response=handle_response, **kwargs)

    def handle_response(self, r: requests.Response) -> None:
        """Base response handling for subclasses"""
        if r.status_code == 404:
            raise NotFoundError(self, r)
        if r.status_code != 200:  # fixme: 200 <= x < 300
            raise NetworkError(self, r)


class ExplorerAPI(BaseAPI):
    pushing: dict[str, str] = NotImplemented

    def process_transaction(self, data: dict[str, typing.Any]) -> BroadcastedTransaction:
        raise NotImplementedError

    def get_address(self, address: BaseAddress) -> AddressInfo:
        raise NotImplementedError

    def get_transaction(self, txid: str) -> BroadcastedTransaction:
        raise NotImplementedError

    def get_transactions(self, txids: list[str]) -> list[BroadcastedTransaction]:
        return list(map(self.get_transaction, txids))

    def get_address_transactions(self, address: BaseAddress, *args, **kwargs) -> list[BroadcastedTransaction]:
        raise NotImplementedError

    def get_unspent(self, address: BaseAddress) -> list[Unspent]:
        raise NotImplementedError

    def head(self) -> Block:
        raise NotImplementedError

    def push(self, tx: Transaction) -> typing.Optional[typing.Any]:
        raise NotImplementedError


class BlockchairAPI(ExplorerAPI):
    uri = {
        NetworkType.MAIN: 'https://api.blockchair.com/bitcoin',
        NetworkType.TEST: 'https://api.blockchair.com/bitcoin/testnet'
    }
    endpoints = {
        'address': '{uri}/dashboards/address/{address}',
        'tx': '{uri}/dashboards/transaction/{txid}',
        'txs': '{uri}/dashboards/transactions/{txids}',
        'head-block': '{uri}/dashboards/block/0',
        'push': '{uri}/push/transaction'
    }
    pushing = {
        'param': 'data'
    }

    def handle_response(self, r: requests.Response):
        if r.status_code in [403, 430]:
            raise ExceededLimitError(self, r)
        return super().handle_response(r)

    def process_transaction(self, data: dict[str, typing.Any]) -> BroadcastedTransaction:  # todo: maybe add get_coinbasetx() and process it (except its havent inputs)
        ins: ioList[UnsignableInput] = ioList()
        if data['transaction'].get('is_coinbase'):
            ins.append(CoinbaseInput(b'', b''))
        for inp in data['inputs']:  # if is_coinbase inputs will be empty
            i = UnsignableInput(bytes.fromhex(inp['transaction_hash']), inp['index'], inp['value'], inp['spending_sequence'])
            i.script = Script.deserialize(inp['spending_signature_hex'])
            i.witness = Script(*inp['spending_witness'].split(','))
            ins.append(i)
        return BroadcastedTransaction(
            ins,
            ioList(Output(Script.deserialize(out['script_hex']), out['value']) for out in data['outputs']),
            data['transaction']['block_id'],
            self.network,
            data['transaction']['version'],
            data['transaction']['lock_time']
        )

    def handle_address_notfound(self, d: dict[str, typing.Any], r: requests.Response):
        """
        Inner method for handling address existence (not in handle_response cause api returns 200 code)
        :param d: address data (data/<address-string>/address)
        """
        if not d['type'] and not d['script_hex']:
            raise NotFoundError(self, r)

    def get_address(self, address: BaseAddress) -> AddressInfo:
        r = self.get('address', address=address.string)
        d = r.json()['data'][address.string]['address']
        self.handle_address_notfound(d, r)
        return AddressInfo(d['received'], d['spent'], d['transaction_count'], address)

    def get_transaction(self, txid: str) -> BroadcastedTransaction:
        r = self.get('tx', txid=txid)
        d = r.json()['data']
        if not d:
            raise NotFoundError(self, r)
        return self.process_transaction(d[txid])

    def get_transactions(self, txids: list[str]) -> list[BroadcastedTransaction]:
        txs: list[BroadcastedTransaction] = []
        for s in range(0, len(txids), 10):  # max 10 txs per request
            cur = txids[s:s + 10]
            r = self.get('txs', txids=','.join(cur), handle_response=False)

            if r.status_code == 400:
                raise NotFoundError(self, r)
            self.handle_response(r)

            d = r.json()['data']
            if not d:
                raise NotFoundError(self, r)
            txs.extend(self.process_transaction(d[tx]) for tx in cur)
        return txs

    def get_address_transactions(self, address: BaseAddress, length: int, offset: int = 0) -> list[BroadcastedTransaction]:
        params = {
            'limit': f'{length},0',
            'offset': f'{offset},0'
        }
        r = self.get('address', {'params': params}, address=address.string)
        d = r.json()['data'][address.string]
        self.handle_address_notfound(d['address'], r)
        return self.get_transactions(d['transactions'])

    def get_unspent(self, address: BaseAddress, limit: int = 1000) -> list[Unspent]:
        r = self.get('address', {'params': { 'limit': f'0,{limit}' }}, address=address.string)  # 0txs 1000utxo by default
        d = r.json()['data'][address.string]
        self.handle_address_notfound(d['address'], r)
        return [Unspent(bytes.fromhex(utxo['transaction_hash']), utxo['index'], utxo['value'], Block(utxo['block_id']), address) for utxo in d['utxo']]

    def head(self) -> Block:
        return Block(self.get('head-block').json()['context']['state'])

    def push(self, tx: Transaction) -> typing.Optional[typing.Any]:
        self.post('push', session_params={'json': { self.pushing['param']: tx.serialize().hex() }})


class BlockstreamAPI(ExplorerAPI):
    uri = {
        NetworkType.MAIN: 'https://blockstream.info/api',
        NetworkType.TEST: 'https://blockstream.info/testnet/api'
    }
    endpoints = {
        'address': '{uri}/address/{address}',
        'tx': '{uri}/tx/{txid}',
        'atxs': '{address_endpoint}/txs',
        'atxs-chaintype': '{address_endpoint}/txs/{type}',  # type: chain/mempool
        'atxs-pag': '{address_endpoint}/txs/{type}/{last_seen_txid}',
        'utxo': '{address_endpoint}/utxo',
        'head-block': '{uri}/blocks/tip/height',
        'push': '{uri}/tx'
    }
    pushing = {
        'param': 'data'
    }

    def handle_response(self, r: requests.Response) -> None:
        if r.status_code == 400:
            if r.text.strip() == 'Too many history entries':
                raise ExcessiveAddress(self, r)
            raise NotFoundError(self, r)
        return super().handle_response(r)

    def process_transaction(self, data: dict[str, typing.Any]) -> BroadcastedTransaction:
        ins: ioList[UnsignableInput] = ioList()
        for inp in data['vin']:
            ins.append(
                CoinbaseInput(
                    inp['scriptsig'],
                    Script(*inp.get('witness', []))
                ) if inp.get('is_coinbase') else UnsignableInput(
                    bytes.fromhex(inp['txid']),
                    inp['vout'],
                    inp['prevout']['value'] if inp['prevout'] else 0,
                    inp['sequence'],
                    Script.deserialize(inp['scriptsig']),
                    Script(*inp.get('witness', []))
                )
            )
        return BroadcastedTransaction(
            ins,
            ioList(Output(Script.deserialize(out['scriptpubkey']), out['value']) for out in data['vout']),
            data['status'].get('block_height', -1),
            self.network,
            data['version'],
            data['locktime']
        )

    def get_address(self, address: BaseAddress) -> AddressInfo:
        d = self.get('address', address=address.string).json()
        _sum = lambda k: d['chain_stats'][k] + d['mempool_stats'][k]
        return AddressInfo(_sum('funded_txo_sum'), _sum('spent_txo_sum'), _sum('tx_count'), address)

    def get_transaction(self, txid: str) -> BroadcastedTransaction:
        return self.process_transaction(self.get('tx', txid=txid).json())

    def get_address_transactions(self,
                                 address: BaseAddress,
                                 last_seen_txid: typing.Optional[str] = None,
                                 handle_overflow: bool = False)  -> list[BroadcastedTransaction]:
        """
        Blockstream returns 50 unconfirmed (mempool) and 25 confirmed transactions.
        Mempool transactions can be more than 50, but Blockstream doesn't process them.

        :param handle_overflow: if true raise error if mempool transactions can be more than Blockstream returns
        """
        if last_seen_txid:
            return list(map(self.process_transaction, self.get(
                'atxs-pag',
                address_endpoint=self.get_endpoint('address', address=address.string),
                type='chain',
                last_seen_txid=last_seen_txid).json()
            ))
        if not handle_overflow:
            return list(map(
                self.process_transaction,
                self.get('atxs', address_endpoint=self.get_endpoint('address', address=address.string)).json()
            ))

        mr = self.get('atxs-chaintype', address_endpoint=self.get_endpoint('address', address=address.string), type='mempool')
        mempool = mr.json()
        if len(mempool) == 50:
            raise AddressOverflowError(self, mr)
        chain = self.get('atxs-chaintype', address_endpoint=self.get_endpoint('address', address=address.string), type='chain').json()
        return list(map(self.process_transaction, mempool + chain))

    def get_unspent(self, address: BaseAddress) -> list[Unspent]:
        r = self.get('utxo', address_endpoint=self.get_endpoint('address', address=address.string))
        return [
            Unspent(
                bytes.fromhex(tx['txid']),
                tx['vout'],
                tx['value'],
                Block(tx['status']['block_height']),
                address
            ) for tx in r.json()
        ]

    def head(self) -> Block:
        return Block(self.get('head-block').text)

    def push(self, tx: RawTransaction) -> typing.Optional[typing.Any]:
        self.post('push', session_params={'data': { self.pushing['param']: tx.serialize().hex() }})


class BlockchainAPI(ExplorerAPI):
    uri = {
        NetworkType.MAIN: 'https://api.blockchain.info/haskoin-store/btc'
    }
    endpoints = {
        'address': '{uri}/address/{address}/balance',
        'tx': '{uri}/transaction/{txid}',
        'txs': '{uri}/transactions',
        'atxs': '{uri}/address/{address}/transactions/full',
        'utxo': '{uri}/address/{address}/unspent',
        'head-block': '{uri}/block/best?notx=true',
        'push': '{uri}/transactions'
    }
    pushing = {}

    def process_transaction(self, data: dict[str, typing.Any]) -> BroadcastedTransaction:
        ins: ioList[UnsignableInput] = ioList()
        for inp in data['inputs']:
            ins.append(
                CoinbaseInput(
                    inp['sigscript'],
                    Script(*inp['witness'])
                ) if inp.get('coinbase') else UnsignableInput(
                    bytes.fromhex(inp['txid']),
                    inp['output'],
                    inp['value'],
                    inp['sequence'],
                    Script.deserialize(inp['sigscript']),
                    Script(*inp['witness'])
                )
            )
        return BroadcastedTransaction(
            ins,
            ioList(Output(Script.deserialize(out['pkscript']), out['value']) for out in data['outputs']),
            Block(data['block'].get('height', -1)),
            self.network,
            data['version'],
            data['locktime']
        )

    def get_address(self, address: BaseAddress) -> AddressInfo:
        d = self.get('address', address=address.string).json()
        received = d['received'] - d['unconfirmed']
        return AddressInfo(received, received - d['confirmed'], d['txs'], address)

    def get_transaction(self, txid: str) -> BroadcastedTransaction:
        d = self.get('tx', txid=txid).json()
        return self.process_transaction(d)

    def get_transactions(self, txids: list[str]) -> list[BroadcastedTransaction]:
        r = self.get('txs', {'params': { 'txids': ','.join(txids) }}, handle_response=False)
        d = r.json()
        if r.status_code == 400 and d['message'].strip() == 'Unable to parse param txids':
            raise NotFoundError(self, r)
        self.handle_response(r)
        return list(map(self.process_transaction, d))

    def get_address_transactions(self, address: BaseAddress, length: int, offset: int = 0)  -> list[BroadcastedTransaction]:
        params = {
            'limit': length,
            'offset': offset
        }
        d = self.get('atxs', {'params': params}, address=address.string).json()
        return list(map(self.process_transaction, d))

    def get_unspent(self, address: BaseAddress) -> list[Unspent]:
        d = self.get('utxo', address=address.string).json()
        return list(map(
            lambda tx: Unspent(
                bytes.fromhex(tx['txid']),
                tx['index'],
                tx['value'],
                Block(tx['block'].get('height', -1)),
                address
            ),
            d
        ))

    def head(self) -> Block:
        return Block(self.get('head-block').json()['height'])

    def push(self, tx: Transaction) -> typing.Optional[typing.Any]:
        self.session.post('', headers={'Content-Type': 'text/plain'}, data=b'')
        return self.post('push', session_params={
            'headers': {
                'accept': 'application/json',
                'Content-Type': 'text/plain'
            },
            'data': tx.serialize().hex()
        })


class BlockcypherAPI(ExplorerAPI):
    uri: dict[NetworkType, str] = NotImplemented
    endpoints: dict[str, str] = NotImplemented
    pushing: dict[str, str] = NotImplemented

    def handle_response(self, r: requests.Response) -> None:
        pass

    def process_transaction(self, data: dict[str, typing.Any]) -> BroadcastedTransaction:
        raise NotImplementedError

    def get_address(self, address: BaseAddress) -> AddressInfo:
        raise NotImplementedError

    def get_transaction(self, txid: str) -> BroadcastedTransaction:
        raise NotImplementedError

    def get_transactions(self, txids: list[str]) -> list[BroadcastedTransaction]:
        return list(map(self.get_transaction, txids))

    def get_address_transactions(self, address: BaseAddress, *args, **kwargs) -> list[BroadcastedTransaction]:
        raise NotImplementedError

    def get_unspent(self, address: BaseAddress) -> list[Unspent]:
        raise NotImplementedError

    def head(self) -> Block:
        raise NotImplementedError

    def push(self, tx: Transaction) -> typing.Optional[typing.Any]:
        raise NotImplementedError


class BitcoreAPI(ExplorerAPI):
    uri = {
        NetworkType.MAIN: 'https://api.bitcore.io/api/BTC/mainnet',
        NetworkType.TEST: 'https://api.bitcore.io/api/BTC/testnet'
    }
    endpoints = {
        'utxo': '{uri}/address/{address}?unspent=true&limit=100',
        'head-block': '{uri}/block/tip',
        'push': '{uri}/tx/send'
    }
    pushing = {
        'param': 'rawTx'
    }

    def handle_response(self, r: requests.Response):
        super().handle_response(r)
        r.raise_for_status()
        return

    def get_unspent(self, address: BaseAddress) -> list[Unspent]:
        d = self.get('utxo', address=address.string).json()

        unspents = []
        while True:
            unspents.extend(Unspent(
                bytes.fromhex(tx['mintTxid']),
                tx['mintIndex'],
                tx['value'],
                Block(tx['mintHeight']),
                address
            ) for tx in d)

            if len(d) < 100:  # limit=100
                break

            d = self.get('utxo', {'params': { 'since': d[-1]['_id'] }}, address=address.string).json()

        return unspents

    def head(self) -> Block:
        return Block(self.get('head-block').json()['height'])

    def push(self, tx: Transaction) -> typing.Optional[typing.Any]:
        self.post('push', session_params={'json': { self.pushing['param']: tx.serialize().hex() }})


class Service(ExplorerAPI):
    """...

    Priority:
    """
    type _api_priority_T = list[type[BaseAPI]]
    type _network_errors_T = list[type[NetworkError] | type[ConnectionError]]

    def __init__(self,
                 network: NetworkType = DEFAULT_NETWORK,
                 basepriority: typing.Optional[_api_priority_T] = None,
                 priority: typing.Optional[dict[typing.Callable, _api_priority_T]] = None,
                 session: typing.Optional[requests.Session] = None,
                 timeout: int = DEFAULT_SERVICE_TIMEOUT,
                 ignored_errors: typing.Optional[_network_errors_T] = None) -> None:
        """
        :param basepriority:
        :param priority:
        """
        super().__init__(network, session, timeout)
        self.basepriority = basepriority or Service.basepriority.copy()
        self.priority = priority or Service.priority.copy()
        self.ignored_errors = ignored_errors or []

    def resolve_priority(self, function: typing.Callable, priority: typing.Optional[_api_priority_T]) -> _api_priority_T:
        """Resolve and filters basepriority, self.priority and default Service.priority"""
        p: Service._api_priority_T = priority or self.priority.get(function, self.basepriority)
        return list(filter(lambda a: a.supports_network(self.network), p))

    def call(self,
             attr: str,
             args: typing.Iterable,
             kwargs: typing.Mapping,
             priority: typing.Optional[_api_priority_T] = None,
             ignored_errors: typing.Optional[_network_errors_T] = None) -> typing.Any:
        p = self.resolve_priority(getattr(Service, attr), priority)
        errors: dict[BaseAPI, Exception] = {}

        for T in p:
            api = T(self.network, self.session, self.timeout)
            method = getattr(api, attr)
            try:
                return method(*args, **kwargs)
            except tuple(ignored_errors or self.ignored_errors) as e:
                errors[api] = e

        raise ServiceError('none of the called api provided a result', attr, p, errors)

    def get_address(self,
                    address: BaseAddress,
                    priority: typing.Optional[_api_priority_T] = None,
                    ignored_errors: typing.Optional[_network_errors_T] = None) -> AddressInfo:
        return self.call('get_address', [address], {}, priority, ignored_errors)

    def get_transaction(self,
                        txid: str,
                        priority: typing.Optional[_api_priority_T] = None,
                        ignored_errors: typing.Optional[_network_errors_T] = None) -> BroadcastedTransaction:
        return self.call('get_transaction', [txid], {}, priority, ignored_errors)

    def get_transactions(self,
                         txids: list[str],
                         priority: typing.Optional[_api_priority_T] = None,
                         ignored_errors: typing.Optional[_network_errors_T] = None) -> list[BroadcastedTransaction]:
        return self.call('get_transactions', [txids], {}, priority, ignored_errors)

    def get_address_transactions(self, address: BaseAddress, *args, **kwargs) -> list[BroadcastedTransaction]:
        """Only BlockstreamAPI is used, pagination between services not implemented"""
        return self.call('get_address_transactions', [address], {}, [BlockstreamAPI])

    def get_unspent(self,
                    address: BaseAddress,
                    priority: typing.Optional[_api_priority_T] = None,
                    ignored_errors: typing.Optional[_network_errors_T] = None) -> list[Unspent]:
        return self.call('get_unspent', [address], {}, priority, ignored_errors)

    def get_unspent_inputs(self, *args: tuple[PrivateKey, BaseAddress]) -> list[Input]:
        return [Input.from_unspent(unspent, pv, address) for pv, address in args for unspent in self.get_unspent(address)]

    def head(self,
             priority: typing.Optional[_api_priority_T] = None,
             ignored_errors: typing.Optional[_network_errors_T] = None) -> Block:
        return self.call('head', [], {}, priority, ignored_errors)

    def push(self,
             tx: Transaction,
             priority: typing.Optional[_api_priority_T] = None,
             ignored_errors: typing.Optional[_network_errors_T] = None) -> typing.Optional[typing.Any]:
        return self.call('push', [tx], {}, priority, ignored_errors)

    def convert_transaction(self,
                            tx: RawTransaction,
                            priority: typing.Optional[_api_priority_T] = None,
                            ignored_errors: typing.Optional[_network_errors_T] = None) -> Transaction:
        return Transaction(
            [UnsignableInput(
                i.txid,
                i.vout,
                self.get_transaction(i.txid.hex(), priority, ignored_errors).outputs[i.vout].amount,
                i.sequence
            ) for i in tx.inputs],
            tx.outputs,
            tx.version,
            tx.locktime
        )

    # == default props ==

    # base priority for any api method
    basepriority: _api_priority_T = [
        BlockchainAPI,
        BlockstreamAPI,
        BlockchairAPI,
        BlockcypherAPI,
        BitcoreAPI
    ]
    # custom priority for each method
    # priority: dict[typing.Callable, _api_priority_T] = {
    #     get_address: [],
    #     get_transaction: [],
    #     get_transactions: [],
    #     get_address_transactions: [],
    #     get_unspent: [],
    #     head: [],
    #     push: []
    # }
    priority: dict[typing.Callable, _api_priority_T] = {}


@dataclass
class FeeRate:
    # block: satoshi
    next: int
    halfhour: int  # 3 blocks
    hour: int  # 6 blocks
    low: int  # ~12 hours (72 blocks)
    minimum: int


class FeeRateAPI(BaseAPI):
    @abstractmethod
    def get_rate() -> FeeRate:
        raise NotImplementedError

    def calcfee(self, vsize: int, rate: typing.Optional[FeeRate] = None) -> FeeRate:
        rate = rate or self.get_rate()
        return FeeRate(
            rate.next * vsize,
            rate.halfhour * vsize,
            rate.hour * vsize,
            rate.low * vsize,
            rate.minimum * vsize
        )


class BitcoinFeesAPI(FeeRateAPI):
    uri = {
        NetworkType.MAIN: 'https://bitcoinfees.net'
    }
    endpoints = {
        'fees': '{uri}/api.json'
    }

    def get_rate(self) -> FeeRate:
        d: dict[str, int] = self.get('fees').json()['fee_by_block_target']
        return FeeRate(*[d[b] // 10 ** 3 for b in ['1', '3', '6', '72', '100']])


class MempoolSpaceAPI(FeeRateAPI):
    uri = {
        NetworkType.MAIN: 'https://mempool.space'
    }
    endpoints = {
        'fees': '{uri}/api/v1/fees/recommended'
    }

    def get_rate(self) -> FeeRate:
        d: dict[str, int] = self.get('fees').json()
        return FeeRate(
            d['fastestFee'],
            d['halfHourFee'],
            d['hourFee'],
            d['economyFee'],
            d['minimumFee']
        )
