from abc import ABC, abstractmethod
from bit.network.services import *


class DefaultAPI(ABC):
    @property
    @abstractmethod
    def MAIN_ADDRESS_API(self) -> str:
        ...

    @property
    @abstractmethod
    def TEST_ADDRESS_API(self) -> str:
        ...

    @classmethod
    def _get_address_info_data(cls, address: str, *, network: str = 'mainnet') -> dict:
        api = cls.TEST_ADDRESS_API if network == 'testnet' else cls.MAIN_ADDRESS_API
        r = requests.get(api.format(address), params={'limit': '1'}, timeout=DEFAULT_TIMEOUT)

        if r.status_code != 200:
            raise ConnectionError

        return r.json()

    @classmethod
    @abstractmethod
    def _get_address_info(cls, address: str, *, network: str = 'mainnet') -> tuple[int, int, int, int]:
        ...

    @classmethod
    def get_address_info(cls, address: str) -> tuple[int, int, int, int]:
        return cls._get_address_info(address)

    @classmethod
    def get_address_info_testnet(cls, address: str) -> tuple[int, int, int, int]:
        return cls._get_address_info(address, network='testnet')

    @classmethod
    @abstractmethod
    def get_balance(cls, address: str) -> int:
        ...

    @classmethod
    @abstractmethod
    def get_balance_testnet(cls, address: str) -> int:
        ...

    @classmethod
    @abstractmethod
    def get_transactions(cls, address: str) -> list[str]:
        ...

    @classmethod
    @abstractmethod
    def get_transactions_testnet(cls, address: str) -> list[str]:
        ...

    @classmethod
    @abstractmethod
    def get_transactions_by_id(cls, txid: str) -> str:
        ...

    @classmethod
    @abstractmethod
    def get_transactions_by_id_testnet(cls, txid: str) -> str:
        ...

    @classmethod
    @abstractmethod
    def get_unspent(cls, address: str) -> list[Unspent]:
        ...

    @classmethod
    @abstractmethod
    def get_unspent_testnet(cls, address: str) -> list[Unspent]:
        ...

    @classmethod
    @abstractmethod
    def broadcast_tx(cls, tx_hex: str) -> bool:
        ...

    @classmethod
    @abstractmethod
    def broadcast_tx_testnet(cls, tx_hex: str) -> bool:
        ...


class BlockchairAPI(BlockchairAPI, DefaultAPI):
    @classmethod
    def _get_address_info(cls, address: str, *, network: str = 'mainnet') -> tuple:
        data = super()._get_address_info_data(address, network=network)
        return data['received'], data['spent'], data['transaction_count'], data['balance']


class BlockstreamAPI(BlockstreamAPI, DefaultAPI):
    @classmethod
    def _get_address_info(cls, address: str, *, network: str = 'mainnet') -> tuple:
        data = super()._get_address_info_data(address, network=network)
        received = data['chain_stats']['funded_txo_sum'] + data['mempool_stats']['funded_txo_sum']
        sent = data['chain_stats']['spent_txo_sum'] + data['mempool_stats']['spent_txo_sum']
        tx_count = data['chain_stats']['tx_count'] + data['mempool_stats']['tx_count']
        balance = received - sent
        return received, sent, tx_count, balance


class BlockchainAPI(BlockchainAPI, DefaultAPI):
    @classmethod
    def _get_address_info(cls, address: str, *, network: str = 'mainnet') -> tuple:
        data = super()._get_address_info_data(address, network=network)
        return data['total_received'], data['total_sent'], data['n_tx'], data['final_balance']

    @classmethod
    def get_address_info_testnet(cls, address: str) -> tuple:
        raise TypeError('BlockchainAPI do not support testnet')


class SmartbitAPI(SmartbitAPI, DefaultAPI):
    @classmethod
    def _get_address_info(cls, address: str, *, network: str = 'mainnet') -> tuple:
        data = super()._get_address_info_data(address, network=network)['address']['total']
        return data['received_int'], data['spent_int'], data['transaction_count'], data['balance_int']


class BlockcypherAPI(DefaultAPI):  # limit: 200 requests/hr
    TOKEN = '68cc80e996b148788878a309246edef5'
    MAIN_ENDPOINT = 'https://api.blockcypher.com/v1/btc/main/'
    MAIN_ADDRESS_API = MAIN_ENDPOINT + 'addrs/{}/balance'
    MAIN_UNSPENT_API = MAIN_ENDPOINT + 'addrs/{}?unspentOnly=true'
    MAIN_TX_PUSH_API = MAIN_ENDPOINT + 'txs/push?token=' + TOKEN
    MAIN_TX_API = MAIN_ENDPOINT + 'txs/{}'
    TEST_ENDPOINT = 'https://api.blockcypher.com/v1/btc/test3/'
    TEST_ADDRESS_API = TEST_ENDPOINT + 'addrs/{}/balance'
    TEST_UNSPENT_API = TEST_ENDPOINT + 'addrs/{}?unspentOnly=true'
    TEST_TX_PUSH_API = TEST_ENDPOINT + 'txs/push?token=' + TOKEN
    TEST_TX_API = TEST_ENDPOINT + 'txs/{}'
    TX_PUSH_PARAM = 'tx'

    @classmethod
    def _get_address_info(cls, address: str, *, network: str = 'mainnet') -> tuple:
        data = super()._get_address_info_data(address, network=network)
        return data['total_received'], data['total_sent'], data['final_n_tx'], data['final_balance']

    @classmethod
    def _get_balance(cls, address: str, *, network: str = 'mainnet') -> int:
        api = cls.TEST_ADDRESS_API if network == 'testnet' else cls.MAIN_ADDRESS_API
        r = requests.get(api.format(address), timeout=DEFAULT_TIMEOUT)

        if r.status_code != 200:
            raise ConnectionError

        return r.json()['final_balance']

    @classmethod
    def get_balance(cls, address: str) -> int:
        return cls._get_balance(address)

    @classmethod
    def get_balance_testnet(cls, address: str) -> int:
        return cls._get_balance(address, network='testnet')

    @classmethod
    def _get_unspent(cls, address: str, *, network: str = 'mainnet') -> list:
        txs_per_page = 1000
        payload = {'limit': str(txs_per_page)}
        api = cls.TEST_UNSPENT_API if network == 'testnet' else cls.MAIN_UNSPENT_API
        r = requests.get(api.format(address), params=payload, timeout=DEFAULT_TIMEOUT)

        if r.status_code != 200:
            raise ConnectionError

        response = r.json()
        unspents = []
        txrefs = response['txrefs'] if 'txrefs' in response else []
        unconfirmed_txrefs = response['unconfirmed_txrefs'] if 'unconfirmed_txrefs' in response else []
        refs = txrefs + unconfirmed_txrefs

        script_pubkey = bytes_to_hex(address_to_scriptpubkey(address))
        unspents.extend(
            Unspent(
                tx['value'],
                tx['confirmations'],
                script_pubkey,
                tx['tx_hash'],
                tx['tx_output_n'],
            )
            for tx in refs
        )

        return unspents

    @classmethod
    def get_unspent(cls, address: str) -> list:
        return cls._get_unspent(address)

    @classmethod
    def get_unspent_testnet(cls, address: str) -> list:
        return cls._get_unspent(address, network='testnet')

    @classmethod
    def _broadcast_tx(cls, tx_hex: str, *, network: str = 'mainnet') -> bool:
        api = cls.TEST_TX_PUSH_API if network == 'testnet' else cls.MAIN_TX_PUSH_API
        r = requests.post(api, json={cls.TX_PUSH_PARAM: tx_hex}, timeout=DEFAULT_TIMEOUT)

        return r.status_code in (200, 201)

    @classmethod
    def broadcast_tx(cls, tx_hex: str) -> bool:
        return cls._broadcast_tx(tx_hex)

    @classmethod
    def broadcast_tx_testnet(cls, tx_hex: str) -> bool:
        return cls._broadcast_tx(tx_hex, network='testnet')


class NetworkAPI(NetworkAPI):
    GET_ADDRESS_INFO_MAIN = [
        BlockstreamAPI.get_address_info,
        BlockcypherAPI.get_address_info,
        BlockchairAPI.get_address_info,
        SmartbitAPI.get_address_info,
        BlockchainAPI.get_address_info,
    ]
    GET_BALANCE_MAIN = [
        BlockstreamAPI.get_balance,
        BlockchainAPI.get_balance,
        SmartbitAPI.get_balance,
        BlockchairAPI.get_balance,
        BitcoreAPI.get_balance,
    ]
    GET_TRANSACTIONS_MAIN = [
        BlockstreamAPI.get_transactions,  # Limit 1000
        BlockchairAPI.get_transactions,  # Limit 1000
        BlockchainAPI.get_transactions,  # No limit, requires multiple requests
        SmartbitAPI.get_transactions,  # Limit 1000
    ]
    GET_TRANSACTION_BY_ID_MAIN = [
        BlockstreamAPI.get_transaction_by_id,
        BlockchairAPI.get_transaction_by_id,
        BlockchainAPI.get_transaction_by_id,
        SmartbitAPI.get_transaction_by_id,
    ]
    GET_UNSPENT_MAIN = [
        BlockstreamAPI.get_unspent,
        BlockcypherAPI.get_unspent,
        BlockchairAPI.get_unspent,
        SmartbitAPI.get_unspent,  # Limit 1000
        BlockchainAPI.get_unspent,
        # BitcoreAPI.get_unspent,  # No limit (?), but bad caching and give bad tx with already used unspent
    ]
    BROADCAST_TX_MAIN = [
        BlockstreamAPI.broadcast_tx,
        BlockchainAPI.broadcast_tx,
        BlockchairAPI.broadcast_tx,
        BlockcypherAPI.broadcast_tx,
        SmartbitAPI.broadcast_tx,  # Limit 5/minute
        BitcoreAPI.broadcast_tx,
    ]

    GET_ADDRESS_INFO_TEST = [
        BlockstreamAPI.get_address_info_testnet,
        BlockcypherAPI.get_address_info_testnet,
        BlockchairAPI.get_address_info_testnet,
        SmartbitAPI.get_address_info_testnet,
    ]
    GET_BALANCE_TEST = [
        BlockstreamAPI.get_balance_testnet,
        SmartbitAPI.get_balance_testnet,
        BlockchairAPI.get_balance_testnet,
        BitcoreAPI.get_balance_testnet,
    ]
    GET_TRANSACTIONS_TEST = [
        BlockstreamAPI.get_transactions_testnet,
        SmartbitAPI.get_transactions_testnet,  # Limit 1000
        BlockchairAPI.get_transactions_testnet,  # Limit 1000
    ]
    GET_TRANSACTION_BY_ID_TEST = [
        BlockstreamAPI.get_transaction_by_id_testnet,
        BlockchairAPI.get_transaction_by_id_testnet,
        SmartbitAPI.get_transaction_by_id
    ]
    GET_UNSPENT_TEST = [
        BlockstreamAPI.get_unspent_testnet,
        BlockcypherAPI.get_unspent_testnet,
        BlockchairAPI.get_unspent_testnet,
        SmartbitAPI.get_unspent_testnet,  # Limit 1000
        # BitcoreAPI.get_unspent_testnet,  # No limit (?), but bad caching and give bad tx with already used unspent
    ]
    BROADCAST_TX_TEST = [
        BlockstreamAPI.broadcast_tx_testnet,  # good
        BlockchairAPI.broadcast_tx_testnet,  # ?
        BlockcypherAPI.broadcast_tx_testnet,
        SmartbitAPI.broadcast_tx_testnet,  # Limit 5/minute
        BitcoreAPI.broadcast_tx_testnet,
    ]

    @classmethod
    def get_address_info(cls, address: str) -> tuple:
        for api_call in cls.GET_ADDRESS_INFO_MAIN:
            try:
                return api_call(address)
            except cls.IGNORED_ERRORS:
                pass

        raise ConnectionError('All APIs are unreachable.')

    @classmethod
    def get_address_info_testnet(cls, address: str) -> tuple:
        for api_call in cls.GET_ADDRESS_INFO_TEST:
            try:
                return api_call(address)
            except cls.IGNORED_ERRORS:
                pass

        raise ConnectionError('All APIs are unreachable.')
