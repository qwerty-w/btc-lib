btc-lib: Simple Bitcoin Library.
=======================

This library is a simple python cold wallet management library for the Bitcoin network. It allows you to generate private/public keys, get Bitcoin addresses from them, create transactions, deserialize already created ones, sign them, sign messages, create multi-signatures and multi-addresses using Bitcoin Script. But its most important difference from most similar libraries is support for Segwit (bech32 encoding) addresses and transactions with them. You can get address using PublicKey.get_address, or create it from your own hash.

**Examples:**

``` python

>>> from btclib import address, Input, Output, Transaction, Service, AddressType, NetworkType
>>>
>>> wif = 'cMtnJjkY8hBrNdNN1kPBCMuTM5h4rxes9nrfRfktTn8tW6HW2pC2'
>>> pv = address.PrivateKey.from_wif(wif)
>>> pb = pv.public
>>> pb.compressed, pb.network
(True, <NetworkType.TEST: 'testnet'>)
>>>
>>> pb = pb.change_network()  # create new instance with toggled network
>>> pb.get_address(AddressType.P2PKH).string
'12Nj1W9U7xvzbRFsMErK8hsm7pYGZv9jsT'
>>>
>>> pb.get_address(AddressType.P2SH_P2WPKH).string
'39YgiFhV8U5rWiUQLh5sDeGJvaft81k1sV'
>>>
>>> pb.get_address(AddressType.P2WPKH).string
'bc1qpuf7m9ysjtnxhpfvx80v6lptsk33lm2x3t9s5w'
>>>
>>> pb.get_address(AddressType.P2WSH).string
'bc1qxmh2drh6xsqyr5m4c8f72fwmqskmgk0rdqtggn6leswzf6m4kxvqhehfwy'
>>>
>>>
>>> pb.network = NetworkType.TEST  # change network in same instance
>>> addr = pb.get_address(AddressType.P2WSH)
>>> addr.string
'tb1qxmh2drh6xsqyr5m4c8f72fwmqskmgk0rdqtggn6leswzf6m4kxvqq3px5t'
>>>
>>> # To see address info:
>>> s = Service(NetworkType.TEST)
>>> ainf = s.get_address(addr)  # request to one of the blockchain APIs
>>> ainf
AddressInfo(received=100000, sent=0, tx_count=1, address=P2WSH.from_string('tb1qxmh2drh6xsqyr5m4c8f72fwmqskmgk0rdqtggn6leswzf6m4kxvqq3px5t'))
>>> ainf.balance
100000
>>>
>>> # Get unspent outputs (UTXO):
>>> utxo = s.get_unspent(addr)
>>> utxo
[Unspent(748131e63a0c27a407316cdafb7cad20ec0994c856862d63e50e706073bc7f00, 0, 100000, block=2103815, address=P2WSH('tb1qxmh2drh6xsqyr5m4c8f72fwmqskmgk0rdqtggn6leswzf6m4kxvqq3px5t'))]
>>>
>>> # Convert unspents to inputs
>>> # Input also contains a private key to be able to sign yourself in a transaction
>>> ins = [Input.from_unspent(u, pv, addr) for u in utxo]
>>> ous = [Output.from_address(address.from_string('tb1q7n075vj7tz4jm28zky7dzknuxujzl5vt6pxkz4'), 90000)]
>>>
>>> tx = Transaction(ins, ous)
>>> tx.default_sign()  # will be used: inp.default_sign() for inp in tx.inputs
>>>
>>> # Notice: inp.default_sign (tx) will try to sign itself in the tx transaction (set the desired inp.script / inp.witness value),
>>> # if inp.address was obtained using PublicKey.get_address, it will succeed, but if the address hash was generated by your custom script,
>>> # and the address object itself was obtained using address.<P2PKH/P2SH/P2WPKH/P2WSH>.from_hash, maybe the signature algorithm will differ
>>> # from the algorithm in inp.default_sign, for this use inp.custom_sign(script=Script(...), witness=Script(...)).
>>> # To summarize: if the address was obtained with PublicKey.get_address(), Input.default_sign will be able to sign it otherwise, use
>>> # inp.custom_sign with custom scripts.
>>>
>>> tx.serialize().hex()
'02000000000101007fbc7360700ee5632d8656c89409ec20ad7cfbda6c3107a4270c3ae63181740000000000ffffffff01905f010000000000160014f4dfea325e58ab2da8e2b13cd...'
>>> tx.id.hex()
'fff79b6d9f6a4068d5b8298c522177e9783af70d61653d628314e155a1e0e94e'
>>> b = s.push(tx)
>>> type(b)
<class 'btclib.transaction.BroadcastedTransaction'>
>>> b.get_confirmations(s.head())
0
>>>
>>> # After a while
>>> b = s.get_transaction(tx.id.hex())
>>> b
{'inputs': [{'txid': '748131e63a0c27a407316cdafb7cad20ec0994c856862d63e50e706073bc7f00', 'vout': 0, 'amount': 100000, 'script': '', 'witness': '473044022072909d3facf0377c1eee3b0000798ca0e76146777a026fd39cbe9307c3d73bb2022007d468e6f9985854d223a5f7742c6f312a48b4cdf9b64a46a6abb75939baf1830125512102e7b47c65a13f84fc934367d3d5be65015f62a56ab103d49df6aa25dacf540c0351ae', 'sequence': 4294967295}], 'outputs': [{'pkscript': '0014f4dfea325e58ab2da8e2b13cd15a7c37242fd18b', 'amount': 90000}], 'version': 2, 'locktime': 0}
>>> b.block
2103822
>>> b.get_confirmations(s.head())
718449
```

This transaction - https://live.blockcypher.com/btc-testnet/tx/fff79b6d9f6a4068d5b8298c522177e9783af70d61653d628314e155a1e0e94e/.

Installation
------------

btc-lib is distributed on `PyPI` and is available on Windows/Linux/macOS
and Windows and supports Python 3.12+.

```bash
$ python3 -m pip install btc-lib
```