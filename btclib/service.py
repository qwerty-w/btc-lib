from abc import ABC, abstractmethod
from collections import namedtuple
from dataclasses import dataclass
from http.client import SERVICE_UNAVAILABLE
from typing import Optional
import typing
import requests

from btclib import transaction
from btclib.address import Address
from btclib.const import NetworkType
from btclib.script import Script
from btclib.transaction import Block, BroadcastedTransaction, RawTransaction, Transaction, UnsignableInput, ioList


@dataclass
class NetworkError(Exception):
    api: 'BaseAPI'
    response: requests.Response

    def __post__init__(self) -> None:
        self.status_code: int = self.response.status_code
        self.request: requests.PreparedRequest = self.response.request


class ExceededLimitError(NetworkError):
    pass


class NotFoundError(NetworkError):
    pass


class ExcessiveAddress(NetworkError):
    pass


class ServiceUnavailableError(NetworkError):
    pass


@dataclass
class AddressInfo:
    received: int
    spent: int
    tx_count: int
    address: Address

    def __post__init__(self) -> None:
        self.balance: int = self.received - self.spent


@dataclass
class Unspent:
    txid: bytes
    vout: int
    amount: int
    block: transaction.Block
    address: Address


# -- Pagination --
# Blockchair:
# через параметры указывается кол-во и оффсет
#
# Blockstream:
# пагинация по last_seen_tx=''
#
# Blockchain:
#
#
#
#


class Pagination:
    @dataclass
    class Page:
        head: str  # txid
        tail: str  # txid
        index: int
        length: int
        service: type['BaseAPI']

    def __init__(self, length: int, length_priority: typing.Literal['<', '=', '>', '><'] = '>') -> None:
        self.history: list[Pagination.Page] = []
        self.length = length
        self.length_priority = length_priority

    def all(self, service: type['BaseAPI']) -> bool:
        return all(service is p.service for p in self.history)

    @property
    def current(self) -> Page:
        return self.history[-1]

    @property
    def offset(self) -> int:
        return self.current.index + self.current.length if self.history else 0

    def back(self) -> typing.Self:
        if self.history:
            self.history.pop()
        return self
    
    def setcur(self, index: int) -> None:
        self.history = self.history[0:index + 1] if index >= 0 else self.history[0:len(self.history) + index + 1]


class BaseAPI(ABC):
    supported_networks: frozenset[NetworkType] = frozenset([NetworkType.MAIN, NetworkType.TEST])
    uri: dict[NetworkType, str] = NotImplemented
    endpoints: dict[str, str] = NotImplemented
    pushing: dict[str, str] = NotImplemented

    _unsupported_network_error = lambda s, n: TypeError(f'{s.__class__.__name__} doesn\'t support {n.value} network')

    def __init__(self, session: requests.Session, network: NetworkType, timeout: int = 10) -> None:
        self.session = session
        self.network = network
        self.timeout = timeout

        if not self.supports_network(network):
            raise self._unsupported_network_error(network)

    @classmethod
    def supports_network(cls, network: NetworkType) -> bool:
        return network in cls.supported_networks

    def toggle_network(self, network: Optional[NetworkType] = None) -> None:
        if network == self.network:
            return
        if not network:
            network = self.network.toggle()
        if not self.supports_network(network):
            raise self._unsupported_network_error(network)

        self.network = network

    def get_endpoint(self, key: str, **kwargs) -> str:
        return self.endpoints[key].format(uri=self.uri[self.network], **kwargs)

    def process_response(self, r: requests.Response) -> None:
        """
        .get and .post methods call this function for process response
        """
        if r.status_code == 404:
            raise NotFoundError(self, r)
        if r.status_code != 200:  # fixme: 200 <= x < 300
            raise NetworkError(self, r)

    def request(self,
                method: str,
                endpoint_key: str,
                session_params: dict[str, typing.Any] = {},
                *,
                process_response: bool = True, **kwargs) -> requests.Response:
        session_params.setdefault('timeout', self.timeout)
        r = self.session.request(method, self.get_endpoint(endpoint_key, **kwargs), **session_params)
        if process_response:
            self.process_response(r)
        return r

    def get(self,
            endpoint_key: str,
            session_params: dict[str, typing.Any] = {},
            *,
            process_response: bool = True,
            **kwargs) -> requests.Response:
        return self.request('GET', endpoint_key, session_params, process_response=process_response, **kwargs)

    def post(self,
             endpoint_key: str,
             session_params: dict[str, typing.Any] = {},
             *,
             process_response: bool = True,
             **kwargs) -> requests.Response:
        return self.request('POST', endpoint_key, session_params, process_response=process_response, **kwargs)

    def get_address(self, address: Address) -> AddressInfo:
        raise NotImplementedError

    def get_transaction(self, txid: str) -> BroadcastedTransaction:
        raise NotImplementedError
    
    def get_transactions(self, txids: list[str]) -> list[BroadcastedTransaction]:
        return list(map(self.get_transaction, txids))

    def get_address_transactions(self, address: Address, pagination: Pagination) -> list[BroadcastedTransaction]:
        raise NotImplementedError

    def get_unspent(self, address: Address) -> list[Unspent]:
        raise NotImplementedError

    def head(self) -> Block:
        raise NotImplementedError

    def push(self, tx: Transaction) -> Optional[typing.Any]:
        raise NotImplementedError


class BlockchairAPI(BaseAPI):
    uri = {
        NetworkType.MAIN: 'https://api.blockchair.com/bitcoin',
        NetworkType.TEST: 'https://api.blockchair.com/bitcoin/testnet'
    }
    endpoints = {
        'address': '{uri}/dashboards/address/{address}',
        'tx': '{uri}/dashboards/transaction/{txid}',
        'txs': '{uri}/dashboards/transactions/{txids}',
        'utxo': '{address_endpoint}?limit=0,1000',  # 0txs 1000utxo
        'head-block': '{uri}/dashboards/block/0',
        'push': '{uri}/push/transaction'
    }
    pushing = {
        'param': 'data'
    }

    def process_response(self, r: requests.Response):
        if r.status_code == 403:
            raise ExceededLimitError(self, r)
        return super().process_response(r)

    def get_address(self, address: Address) -> AddressInfo:
        r = self.get('address', address=address.string)
        d = r.json()['data'][address]['address']
        return AddressInfo(d['received'], d['spent'], d['transaction_count'], address)
    
    def process_transaction(self, data: dict) -> BroadcastedTransaction:
        ins: ioList[UnsignableInput] = ioList()
        for inp in data['inputs']:
            i = transaction.UnsignableInput(inp['transaction_hash'], inp['index'], inp['value'])
            i.script = Script.deserialize(inp['spending_signature_hex'])
            i.witness = Script(*inp['spending_witness'].split(','))
            ins.append(i)

        ous = ioList(transaction.Output(out['script_hex'], out['value']) for out in data['outputs'])
        tx = Transaction(ins, ous, data['transaction']['version'], data['transaction']['lock_time'])
        return BroadcastedTransaction(tx, data['transaction']['block_id'], self.network)

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
            r = self.get('txs', txids=','.join(cur), process_response=False)

            if r.status_code == 400:
                raise NotFoundError(self, r)
            self.process_response(r)

            d = r.json()['data']
            txs.extend(self.process_transaction(d[tx]) for tx in cur)
        return txs

    def get_address_transactions(self, address: Address, pagination: Pagination) -> list[BroadcastedTransaction]:  # todo:
        previous: Pagination.Page = pagination.current

        if previous.service is not BlockchairAPI:
            d: list[str] = []
            while pagination.current.tail not in d:

            
            


        params = {
            'limit': f'{pagination.length},0',
            'offset': f'{pagination.offset},0'
        }
        r = self.get('address', {'params': params}, address=address.string)

        d = r.json()['data']
        if not d:
            return []
        d = d[address.string]['transactions']

        pagination.history.append(pagination.Page(d[0], d[-1], pagination.offset, pagination.length))
        return self.get_transactions(d)

    def get_unspent(self, address: Address) -> list[Unspent]:
        r = self.get('utxo', address_endpoint=self.get_endpoint('address', address=address.string))
        d = r.json()['data'][address.string]['utxo']
        return [Unspent(utxo['transaction_hash'], utxo['index'], utxo['value'], transaction.Block(utxo['block_id']), address) for utxo in d]

    def head(self) -> Block:
        return transaction.Block(self.get('head-block').json()['context']['state'])

    def push(self, tx: Transaction) -> Optional[typing.Any]:
        self.post('push', session_params={'json': { self.pushing['param']: tx.serialize().hex() }})


class BlockstreamAPI(BaseAPI):
    uri = {
        NetworkType.MAIN: 'https://blockstream.info/api',
        NetworkType.TEST: 'https://blockstream.info/testnet/api'
    }
    endpoints = {
        'address': '{uri}/address/{address}',
        'tx': '{uri}/tx/{txid}',
        'atxs': '',
        'utxo': '{address_endpoint}/utxo',
        'head-block': '{uri}/blocks/tip/height',
        'push': '{uri}/tx'
    }
    pushing = {
        'param': 'data'
    }

    def get_address(self, address: Address) -> AddressInfo:
        d = self.get('address', address=address.string).json()
        _sum = lambda k: d['chain_stats'][k] + d['mempool_stats'][k]
        return AddressInfo(_sum('funded_txo_sum'), _sum('spent_txo_sum'), _sum('tx_count'), address)

    def get_transaction(self, txid: str) -> BroadcastedTransaction:
        d = self.get('tx', txid=txid).json()

        ins: ioList[UnsignableInput] = ioList()
        for inp in d['vin']:
            i = UnsignableInput(inp['txid'], inp['vout'], inp['prevout']['value'] if inp['prevout'] else 0, inp['sequence'])
            i.script = Script.deserialize(inp['scriptsig'])
            i.witness = Script(*inp.get('witness', []))

            ins.append(i)

        outs = ioList(transaction.Output(out['script_pub_key'], out['value']) for out in d['vout'])
        tx = Transaction(ins, outs, d['version'], d['locktime'])
        return BroadcastedTransaction(tx, d['status'].get('block_height', -1), self.network)

    def get_address_transactions(self, address: Address, pagination: typing.Optional[Pagination] = None)  -> list[BroadcastedTransaction]:
        raise NotImplementedError

    def get_unspent(self, address: Address) -> list[Unspent]:
        r = self.get('utxo', address_endpoint=self.get_endpoint('address', address=address.string))
        if r.status_code == 400 and r.text == 'Too many history entries':
            raise ExcessiveAddress(self, r)
        return [
            Unspent(
                tx['txid'].encode(),
                tx['vout'],
                tx['value'],
                transaction.Block(tx['status']['block_height']),
                address
            ) for tx in r.json()
        ]

    def head(self) -> Block:
        return transaction.Block(self.get('head-block').text)

    def push(self, tx: RawTransaction) -> Optional[typing.Any]:  # todo: check on BroadcastedTransaction
        self.post('push', session_params={'data': { self.pushing['param']: tx.serialize().hex() }})


class BitcoreAPI(BaseAPI):
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

    def process_response(self, r: requests.Response):
        super().process_response(r)
        r.raise_for_status()
        return

    def get_unspent(self, address: Address) -> list[Unspent]:
        d = self.get('utxo', address=address.string).json()

        unspents = []
        while True:
            unspents.extend(Unspent(
                tx['mintTxid'],
                tx['mintIndex'],
                tx['value'],
                transaction.Block(tx['mintHeight']),
                address
            ) for tx in d)

            if len(d) < 100:  # limit=100
                break

            d = self.get('utxo', {'params': { 'since': d[-1]['_id'] }}, address=address.string).json()

        return unspents

    def head(self) -> Block:
        return transaction.Block(self.get('head-block').json()['height'])

    def push(self, tx: Transaction) -> Optional[typing.Any]:
        self.post('push', session_params={'json': { self.pushing['param']: tx.serialize().hex() }})


class BlockchainAPI(BaseAPI):
    supported_networks = frozenset([NetworkType.MAIN])
    uri = {
        NetworkType.MAIN: 'https://api.blockchain.info/haskoin-store/btc'
    }
    endpoints = {
        'address': '{uri}/address/{address}/balance',
        'tx': '{uri}/transaction/{txid}',
        'atxs': '',
        'utxo': '{uri}/address/{address}/unspent',
        'head-block': '{uri}/block/best?notx=true',
        'push': '{uri}/transactions'
    }
    pushing = {}

    def get_address(self, address: Address) -> AddressInfo:
        d = self.get('address', address=address.string).json()
        received = d['received'] - d['unconfirmed']
        return AddressInfo(received, received - d['confirmed'], d['txs'], address)

    def get_transaction(self, txid: str) -> BroadcastedTransaction:
        d = self.get('tx', txid=txid).json()

        ins: ioList[UnsignableInput] = ioList()
        for inp in d['vin']:
            i = UnsignableInput(inp['txid'], inp['output'], inp['value'], inp['sequence'])
            i.script = Script.deserialize(inp['sigscript'])
            i.witness = Script(*inp['witness'])

            ins.append(i)

        ous = ioList(transaction.Output(out['pkscript'], out['value']) for out in d['out'])
        tx = Transaction(ins, ous, d['version'], d['locktime'])
        return BroadcastedTransaction(tx, transaction.Block(d['block'].get('height', -1)), self.network)

    def get_address_transactions(self, address: Address, pagination: typing.Optional[Pagination] = None)  -> list[BroadcastedTransaction]:
        raise NotImplementedError

    def get_unspent(self, address: Address) -> list[Unspent]:
        d = self.get('utxo', address=address.string).json()
        return list(map(
            lambda tx: Unspent(
                tx['txid'],
                tx['index'],
                tx['value'],
                transaction.Block(tx['block'].get('height', -1)),
                address
            ),
            d
        ))

    def head(self) -> Block:
        return transaction.Block(self.get('head-block').json()['height'])

    def push(self, tx: Transaction) -> Optional[typing.Any]:
        self.session.post('', headers={'Content-Type': 'text/plain'}, data=b'')
        return self.post('push', session_params={
            'headers': {
                'accept': 'application/json',
                'Content-Type': 'text/plain'
            },
            'data': tx.serialize().hex()
        })





class NetworkAPI:
    def __init__(self) -> None:
        self.session = requests.Session()

    def get_address(self) -> AddressInfo:
        pass

    def get_transaction(self) -> Transaction:
        pass

    def get_address_transactions(self) -> list[BroadcastedTransaction]:
        pass

    def get_unspent(self) -> list[Unspent]:
        pass

    def push(self) -> None:
        pass


api = NetworkAPI()