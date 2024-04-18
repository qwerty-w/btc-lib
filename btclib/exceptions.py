from string import Formatter


class Error(Exception):
    msg: str
    unknown_value = '<unknown>'

    def __init__(self, *args, **kwargs):

        for _ in range(sum(1 for x in Formatter().parse(self.msg) if x[1] is not None) - len(args)):
            args += self.unknown_value,

        self.msg = self.msg.format(*args, **kwargs)

    def __str__(self):
        return self.msg


class InvalidError(Error):
    msg = 'INVALID ERROR'


class InvalidAddress(InvalidError):
    msg = 'invalid address - {} (type - {}, network - {})'


class InvalidAddressInstanceType(InvalidError):
    msg = 'invalid address instance - {}'


class InvalidHash160(InvalidError):
    msg = 'invalid hash160 - {}'


class InvalidWIF(InvalidError):
    msg = 'invalid WIF (checksum not verified) - {}'


class InvalidCompressionFormat(InvalidError):  # todo: remove
    msg = 'invalid compression format - {}'


class InvalidScriptPubKey(InvalidError):
    msg = 'invalid scriptPubKey - {}'


class InvalidHexOrOpcode(InvalidError):
    msg = 'hex/opcode expected, \'{}\' received'


class InvalidInputScriptData(InvalidError):
    msg = 'str/bytes/int expected, {} received'


class InvalidByteorder(InvalidError):
    msg = '"little"/"big" expected, {} received'


class InvalidSignatureLength(InvalidError):  # todo: remove
    msg = 'decoded signature length should be 65, but {} received'


class InvalidRecoveryID(InvalidError):  # todo: remove
    msg = 'recovery id should be 27 <= rec_id <= 34, but {} received'


class UnsupportError(Error):
    msg = 'UNSUPPORT ERROR'


class UnsupportedAddressType(UnsupportError):
    msg = 'unsupported type - {}, support only P2PKH, P2SH-P2WPKH (P2SH class), P2WPKH, P2WSH'


class DefaultSignError(Error):
    msg = 'DEFAULT_SIGN ERROR'


class DefaultSignRequiresAddress(DefaultSignError):
    msg = 'Input.address (BitcoinAddress) required for the default_sign is not set or set to a different type'


class DefaultSignRequiresPrivateKey(DefaultSignError):
    msg = 'Input.pv (PrivateKey) required for the default_sign is not set or set to a different type'


class DefaultSignSupportOnlyP2shP2wpkh(DefaultSignError):
    msg = 'from P2SH addresses default_sign supports P2SH-P2WPKH input only, but other type received'


class OutAmountMoreInputAmount(Error):
    msg = 'output amount ({}) more than input amount ({})'


class SighashSingleRequiresInputAndOutputWithSameIndexes(Error):
    msg = 'sighash single signs the output with the same index as the input, the input index is {}, output with ' \
          'that index don\'t exists'


class SegwitHash4SignRequiresInputAmount(Error):
    msg = 'for Transaction.get_hash4sign(input_index, ..., segwit=True) requires Input.amount is not None'


class FailedToGetTransactionData(Error):
    msg = 'failed to connect to get transaction {} data'


class IntSizeGreaterThanMaxSize(Error):
    msg = 'received int ({}) is greater than the max size ({} bytes)'


class UintGotSint(Error):
    msg = 'unsigned int got signed int (for {} use sint)'


class HexLengthMustBeMultipleTwo(Error):
    msg = 'hex expected, his length multiple of two'


class VarIntOnlySupportsUnsignedInt(Error):
    msg = 'varint only supports unsigned int, but {} received'
