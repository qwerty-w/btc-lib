

MAX_ORDER = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141
P = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f

DEFAULT_VERSION = 2
DEFAULT_LOCKTIME = 0
DEFAULT_WITNESS_VERSION = 0
DEFAULT_SEQUENCE = 4294967295
DEFAULT_NETWORK = 'mainnet'

EMPTY_SEQUENCE = 0

NEGATIVE_SATOSHI = -1

SEPARATORS = {
    'default': {
        b'\x4c': 1,
        b'\x4d': 2,
        b'\x4e': 4
    },
    'increased': {
        b'\xfd': 2,
        b'\xfe': 4,
        b'\xff': 8
    }
}
SEPARATORS_REVERSED = {
    'default': {
        1: b'\x4c',
        2: b'\x4d',
        4: b'\x4e'
    },
    'increased': {
        2: b'\xfd',
        4: b'\xfe',
        8: b'\xff'
    }
}

PREFIXES = {
    'wif': {
        'mainnet': b'\x80',
        'testnet': b'\xef'
    },
    'P2PKH': {
        'mainnet': b'\x00',
        'testnet': b'\x6f'
    },
    'P2SH': {
        'mainnet': b'\x05',
        'testnet': b'\xc4'
    },
    'bech32': {
        'mainnet': 'bc',
        'testnet': 'tb'
    }
}

SIGHASHES = {
    'all': 0x01,
    'none': 0x02,
    'single': 0x03,
    'anyonecanpay': 0x80
}

# noinspection SpellCheckingInspection
OP_CODES = {
    # constants
    'OP_0'                  : b'\x00',
    'OP_FALSE'              : b'\x00',
    'OP_PUSHDATA1'          : b'\x4c',
    'OP_PUSHDATA2'          : b'\x4d',
    'OP_PUSHDATA4'          : b'\x4e',
    'OP_1NEGATE'            : b'\x4f',
    'OP_1'                  : b'\x51',
    'OP_TRUE'               : b'\x51',
    'OP_2'                  : b'\x52',
    'OP_3'                  : b'\x53',
    'OP_4'                  : b'\x54',
    'OP_5'                  : b'\x55',
    'OP_6'                  : b'\x56',
    'OP_7'                  : b'\x57',
    'OP_8'                  : b'\x58',
    'OP_9'                  : b'\x59',
    'OP_10'                 : b'\x5a',
    'OP_11'                 : b'\x5b',
    'OP_12'                 : b'\x5c',
    'OP_13'                 : b'\x5d',
    'OP_14'                 : b'\x5e',
    'OP_15'                 : b'\x5f',
    'OP_16'                 : b'\x60',

    # flow control
    'OP_NOP'                : b'\x61',
    'OP_IF'                 : b'\x63',
    'OP_NOTIF'              : b'\x64',
    'OP_ELSE'               : b'\x67',
    'OP_ENDIF'              : b'\x68',
    'OP_VERIFY'             : b'\x69',
    'OP_RETURN'             : b'\x6a',

    # stack
    'OP_TOALTSTACK'         : b'\x6b',
    'OP_FROMALTSTACK'       : b'\x6c',
    'OP_IFDUP'              : b'\x73',
    'OP_DEPTH'              : b'\x74',
    'OP_DROP'               : b'\x75',
    'OP_DUP'                : b'\x76',
    'OP_NIP'                : b'\x77',
    'OP_OVER'               : b'\x78',
    'OP_PICK'               : b'\x79',
    'OP_ROLL'               : b'\x7a',
    'OP_ROT'                : b'\x7b',
    'OP_SWAP'               : b'\x7c',
    'OP_TUCK'               : b'\x7d',
    'OP_2DROP'              : b'\x6d',
    'OP_2DUP'               : b'\x6e',
    'OP_3DUP'               : b'\x6f',
    'OP_2OVER'              : b'\x70',
    'OP_2ROT'               : b'\x71',
    'OP_2SWAP'              : b'\x72',

    # splice
    # 'OP_CAT'                : b'\x7e',
    # 'OP_SUBSTR'             : b'\x7f',
    # 'OP_LEFT'               : b'\x80',
    # 'OP_RIGHT'              : b'\x81',
    'OP_SIZE'               : b'\x82',

    # bitwise logic
    # 'OP_INVERT'             : b'\x83',
    # 'OP_AND'                : b'\x84',
    # 'OP_OR'                 : b'\x85',
    # 'OP_XOR'                : b'\x86',
    'OP_EQUAL'              : b'\x87',
    'OP_EQUALVERIFY'        : b'\x88',

    # arithmetic
    'OP_1ADD'               : b'\x8b',
    'OP_1SUB'               : b'\x8c',
    # 'OP_2MUL'               : b'\x8d',
    # 'OP_2DIV'               : b'\x8e',
    'OP_NEGATE'             : b'\x8f',
    'OP_ABS'                : b'\x90',
    'OP_NOT'                : b'\x91',
    'OP_0NOTEQUAL'          : b'\x92',
    'OP_ADD'                : b'\x93',
    'OP_SUB'                : b'\x94',
    # 'OP_MUL'                : b'\x95',
    # 'OP_DIV'                : b'\x96',
    # 'OP_MOD'                : b'\x97',
    # 'OP_LSHIFT'             : b'\x98',
    # 'OP_RSHIFT'             : b'\x99',
    'OP_BOOLAND'            : b'\x9a',
    'OP_BOOLOR'             : b'\x9b',
    'OP_NUMEQUAL'           : b'\x9c',
    'OP_NUMEQUALVERIFY'     : b'\x9d',
    'OP_NUMNOTEQUAL'        : b'\x9e',
    'OP_LESSTHAN'           : b'\x9f',
    'OP_GREATERTHAN'        : b'\xa0',
    'OP_LESSTHANOREQUAL'    : b'\xa1',
    'OP_GREATERTHANOREQUAL' : b'\xa2',
    'OP_MIN'                : b'\xa3',
    'OP_MAX'                : b'\xa4',
    'OP_WITHIN'             : b'\xa5',

    # crypto
    'OP_RIPEMD160'          : b'\xa6',
    'OP_SHA1'               : b'\xa7',
    'OP_SHA256'             : b'\xa8',
    'OP_HASH160'            : b'\xa9',
    'OP_HASH256'            : b'\xaa',
    'OP_CODESEPARATOR'      : b'\xab',
    'OP_CHECKSIG'           : b'\xac',
    'OP_CHECKSIGVERIFY'     : b'\xad',
    'OP_CHECKMULTISIG'      : b'\xae',
    'OP_CHECKMULTISIGVERIFY': b'\xaf',

    # locktime
    'OP_NOP2'               : b'\xb1',
    'OP_CHECKLOCKTIMEVERIFY': b'\xb1',
    'OP_NOP3'               : b'\xb2',
    'OP_CHECKSEQUENCEVERIFY': b'\xb2'
}

# noinspection SpellCheckingInspection
CODE_OPS = {
    # constants
    b'\x00':    'OP_0'                  ,
    b'\x4c':    'OP_PUSHDATA1'          ,
    b'\x4d':    'OP_PUSHDATA2'          ,
    b'\x4e':    'OP_PUSHDATA4'          ,
    b'\x4f':    'OP_1NEGATE'            ,
    b'\x51':    'OP_1'                  ,
    b'\x52':    'OP_2'                  ,
    b'\x53':    'OP_3'                  ,
    b'\x54':    'OP_4'                  ,
    b'\x55':    'OP_5'                  ,
    b'\x56':    'OP_6'                  ,
    b'\x57':    'OP_7'                  ,
    b'\x58':    'OP_8'                  ,
    b'\x59':    'OP_9'                  ,
    b'\x5a':    'OP_10'                 ,
    b'\x5b':    'OP_11'                 ,
    b'\x5c':    'OP_12'                 ,
    b'\x5d':    'OP_13'                 ,
    b'\x5e':    'OP_14'                 ,
    b'\x5f':    'OP_15'                 ,
    b'\x60':    'OP_16'                 ,

    # flow control
    b'\x61':    'OP_NOP'                ,
    b'\x63':    'OP_IF'                 ,
    b'\x64':    'OP_NOTIF'              ,
    b'\x67':    'OP_ELSE'               ,
    b'\x68':    'OP_ENDIF'              ,
    b'\x69':    'OP_VERIFY'             ,
    b'\x6a':    'OP_RETURN'             ,

    # stack
    b'\x6b':    'OP_TOALTSTACK'         ,
    b'\x6c':    'OP_FROMALTSTACK'       ,
    b'\x73':    'OP_IFDUP'              ,
    b'\x74':    'OP_DEPTH'              ,
    b'\x75':    'OP_DROP'               ,
    b'\x76':    'OP_DUP'                ,
    b'\x77':    'OP_NIP'                ,
    b'\x78':    'OP_OVER'               ,
    b'\x79':    'OP_PICK'               ,
    b'\x7a':    'OP_ROLL'               ,
    b'\x7b':    'OP_ROT'                ,
    b'\x7c':    'OP_SWAP'               ,
    b'\x7d':    'OP_TUCK'               ,
    b'\x6d':    'OP_2DROP'              ,
    b'\x6e':    'OP_2DUP'               ,
    b'\x6f':    'OP_3DUP'               ,
    b'\x70':    'OP_2OVER'              ,
    b'\x71':    'OP_2ROT'               ,
    b'\x72':    'OP_2SWAP'              ,

    # splice
    b'\x82':    'OP_SIZE'               ,

    # bitwise logic
    b'\x87':    'OP_EQUAL'              ,
    b'\x88':    'OP_EQUALVERIFY'        ,

    # arithmetic
    b'\x8b':    'OP_1ADD'               ,
    b'\x8c':    'OP_1SUB'               ,
    b'\x8f':    'OP_NEGATE'             ,
    b'\x90':    'OP_ABS'                ,
    b'\x91':    'OP_NOT'                ,
    b'\x92':    'OP_0NOTEQUAL'          ,
    b'\x93':    'OP_ADD'                ,
    b'\x94':    'OP_SUB'                ,
    b'\x9a':    'OP_BOOLAND'            ,
    b'\x9b':    'OP_BOOLOR'             ,
    b'\x9c':    'OP_NUMEQUAL'           ,
    b'\x9d':    'OP_NUMEQUALVERIFY'     ,
    b'\x9e':    'OP_NUMNOTEQUAL'        ,
    b'\x9f':    'OP_LESSTHAN'           ,
    b'\xa0':    'OP_GREATERTHAN'        ,
    b'\xa1':    'OP_LESSTHANOREQUAL'    ,
    b'\xa2':    'OP_GREATERTHANOREQUAL' ,
    b'\xa3':    'OP_MIN'                ,
    b'\xa4':    'OP_MAX'                ,
    b'\xa5':    'OP_WITHIN'             ,

    # crypto
    b'\xa6':    'OP_RIPEMD160'          ,
    b'\xa7':    'OP_SHA1'               ,
    b'\xa8':    'OP_SHA256'             ,
    b'\xa9':    'OP_HASH160'            ,
    b'\xaa':    'OP_HASH256'            ,
    b'\xab':    'OP_CODESEPARATOR'      ,
    b'\xac':    'OP_CHECKSIG'           ,
    b'\xad':    'OP_CHECKSIGVERIFY'     ,
    b'\xae':    'OP_CHECKMULTISIG'      ,
    b'\xaf':    'OP_CHECKMULTISIGVERIFY',

    # locktime
    b'\xb1':    'OP_CHECKLOCKTIMEVERIFY',
    b'\xb2':    'OP_CHECKSEQUENCEVERIFY'
}
