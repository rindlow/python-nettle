from typing import NotRequired, TypedDict

import docstrings


class CipherParam(TypedDict):
    name: str
    headers: list[str]
    docstring: str
    family: NotRequired[str]
    invert: NotRequired[bool]
    keywrap: NotRequired[bool]
    lenparam: NotRequired[bool]
    nonce: NotRequired[bool]
    parity: NotRequired[bool]
    stream: NotRequired[bool]
    twofuncs: NotRequired[bool]
    twokeys: NotRequired[bool]
    variable_keylen: NotRequired[bool]

class CipherModeParam(TypedDict):
    name: str
    headers: list[str]
    docstring: str
    iv: str
    aead: NotRequired[bool]
    digest_cipher_param: NotRequired[bool]
    know_len: NotRequired[bool]
    mode_key: NotRequired[bool]
    set_cipher_param: NotRequired[bool]
    twofuncs: NotRequired[bool]
    update_cipher_param: NotRequired[bool]


class ExceptionParam(TypedDict):
    name: str
    docstring: str
    base: str


class HashParam(TypedDict):
    name: str
    headers: list[str]
    docstring: str
    context: NotRequired[str]
    digest: NotRequired[bool]
    shake: NotRequired[bool]

class MacParam(TypedDict):
    name: str
    headers: list[str]
    docstring: str
    digest: NotRequired[str]
    nonce: NotRequired[str]

class RandomParam(TypedDict):
    name: str
    headers: list[str]
    docstring: str
    seedsize: str
    seedfunc: NotRequired[bool]

hashes: list[HashParam] = [
    {'name': 'GOSTHash94', 'headers': ['gosthash94.h'],
     'docstring': docstrings.gosthash94},
    {'name': 'MD2', 'headers': ['md2.h'], 'docstring': docstrings.md2},
    {'name': 'MD4', 'headers': ['md4.h'], 'docstring': docstrings.md4},
    {'name': 'MD5', 'headers': ['md5.h'], 'docstring': docstrings.md5},
    {'name': 'RIPEMD160', 'headers': ['ripemd160.h'],
     'docstring': docstrings.ripemd160},
    {'name': 'SHA1', 'headers': ['sha1.h'], 'docstring': docstrings.sha1},
    {'name': 'SHA224', 'headers': ['sha2.h'], 'docstring': docstrings.sha224},
    {'name': 'SHA256', 'headers': ['sha2.h'], 'docstring': docstrings.sha256},
    {'name': 'SHA512', 'headers': ['sha2.h'], 'docstring': docstrings.sha512},
    {'name': 'SHA384', 'headers': ['sha2.h'], 'docstring': docstrings.sha384},
    {'name': 'SHA512_224', 'headers': ['sha2.h'],
     'docstring': docstrings.sha384},
    {'name': 'SHA512_256', 'headers': ['sha2.h'],
     'docstring': docstrings.sha384},
    {'name': 'SHA3_128', 'headers': ['sha3.h'], 'digest': False, 'shake': True,
     'docstring': docstrings.sha3_224, 'context': 'sha3_ctx'},
    {'name': 'SHA3_224', 'headers': ['sha3.h'],
     'docstring': docstrings.sha3_224, 'context': 'sha3_ctx'},
    {'name': 'SHA3_256', 'headers': ['sha3.h'], 'shake': True,
     'docstring': docstrings.sha3_256, 'context': 'sha3_ctx'},
    {'name': 'SHA3_384', 'headers': ['sha3.h'],
     'docstring': docstrings.sha3_384, 'context': 'sha3_ctx'},
    {'name': 'SHA3_512', 'headers': ['sha3.h'],
     'docstring': docstrings.sha3_512, 'context': 'sha3_ctx'},
    {'name': 'Streebog512', 'headers': ['streebog.h'],
     'docstring': docstrings.streebog_512},
    {'name': 'Streebog256', 'headers': ['streebog.h'],
     'docstring': docstrings.streebog_256},
    {'name': 'SM3', 'headers': ['sm3.h'],
     'docstring': docstrings.sm3} ]


ciphers: list[CipherParam] = [
    {'name': 'AES128', 'family': 'aes', 'headers': ['aes.h', 'nist-keywrap.h'],
     'docstring': docstrings.aes, 'keywrap': True,
     'twokeys': True, 'twofuncs': True, 'invert': True},
    {'name': 'AES192', 'family': 'aes', 'headers': ['aes.h', 'nist-keywrap.h'],
     'docstring': docstrings.aes, 'keywrap': True,
     'twokeys': True, 'twofuncs': True, 'invert': True},
    {'name': 'AES256', 'family': 'aes', 'headers': ['aes.h', 'nist-keywrap.h'],
     'docstring': docstrings.aes, 'keywrap': True,
     'twokeys': True, 'twofuncs': True, 'invert': True},
    {'name': 'Arcfour', 'headers': ['arcfour.h'],
     'docstring': docstrings.arcfour,
     'lenparam': True, 'variable_keylen': True, 'stream': True},
    {'name': 'Arctwo', 'headers': ['arctwo.h'],
     'docstring': docstrings.arctwo, 'lenparam': True,
     'twofuncs': True, 'variable_keylen': True},
    {'name': 'Blowfish', 'family': 'blowfish',
     'headers': ['blowfish.h'],
     'docstring': docstrings.blowfish,
     'lenparam': True, 'twofuncs': True, 'variable_keylen': True},
    {'name': 'Camellia128', 'family': 'camellia', 'headers': ['camellia.h'],
     'docstring': docstrings.camellia,
     'twokeys': True, 'invert': True},
    {'name': 'Camellia192', 'family': 'camellia', 'headers': ['camellia.h'],
     'docstring': docstrings.camellia,
     'twokeys': True, 'invert': True},
    {'name': 'Camellia256', 'family': 'camellia', 'headers': ['camellia.h'],
     'docstring': docstrings.camellia,
     'twokeys': True, 'invert': True},
    {'name': 'CAST128', 'family': 'cast128', 'headers': ['cast128.h'],
     'docstring': docstrings.cast128,
     'twofuncs': True},
    {'name': 'ChaCha', 'headers': ['chacha.h'],
     'docstring': docstrings.chacha,
     'nonce': True},
    {'name': 'DES', 'family': 'des', 'headers': ['des.h'],
     'docstring': docstrings.des,
     'twofuncs': True, 'parity': True},
    {'name': 'DES3', 'family': 'des', 'headers': ['des.h'],
     'docstring': docstrings.des,
     'twofuncs': True, 'parity': True},
    {'name': 'Salsa20', 'headers': ['salsa20.h'],
     'docstring': docstrings.salsa20,
     'lenparam': True, 'nonce': True},
    {'name': 'Serpent', 'family': 'serpent', 'headers': ['serpent.h'],
     'docstring': docstrings.serpent,
     'lenparam': True, 'twofuncs': True, 'variable_keylen': True},
    {'name': 'SM4', 'family': 'sm4', 'headers': ['sm4.h'],
     'docstring': docstrings.sm4, 'twokeys': True, },
    {'name': 'Twofish', 'family': 'twofish', 'headers': ['twofish.h'],
     'docstring': docstrings.twofish,
     'lenparam': True, 'twofuncs': True, 'variable_keylen': True},
]



ciphermodes: list[CipherModeParam] = [
    {'name': 'CBC', 'docstring': 'Cipher Block Chaining',
     'headers': ['cbc.h'], 'iv': 'iv', 'twofuncs': True},
    {'name': 'CTR', 'docstring': 'Counter Mode',
     'headers': ['ctr.h'], 'iv': 'ctr'},
    {'name': 'GCM', 'docstring': 'Galois Counter Mode',
     'headers': ['gcm.h'], 'iv': 'iv', 'aead': True,
     'mode_key': True, 'digest_cipher_param': True, },
    {'name': 'EAX', 'docstring': 'The EAX mode is an AEAD mode which'
     ' combines CTR mode encryption, with a message authentication'
     ' based on CBC', 'headers': ['eax.h'],
     'iv': 'nonce', 'aead': True, 'mode_key': True,
     'update_cipher_param': True, 'digest_cipher_param': True,
     'set_cipher_param': True},
    {'name': 'CCM', 'docstring': 'Counter with Cipher Block Chaining'
     '-Message Authentication Code', 'headers': ['ccm.h'],
     'iv': 'nonce', 'aead': True, 'know_len': True,
     'update_cipher_param': True, 'digest_cipher_param': True,
     'set_cipher_param': True},
]



macs: list[MacParam] = [
    {'name': 'HMAC_SHA1', 'headers': ['hmac.h'],
     'docstring': docstrings.hmac,
     'digest': 'SHA1'},
    {'name': 'HMAC_SHA256', 'headers': ['hmac.h'],
     'docstring': docstrings.hmac,
     'digest': 'SHA256'},
    {'name': 'HMAC_SHA512', 'headers': ['hmac.h'],
     'docstring': docstrings.hmac,
     'digest': 'SHA512'},
    {'name': 'UMAC32', 'headers': ['umac.h'],
     'docstring': docstrings.umac,
     'nonce': 'variable'},
    {'name': 'UMAC64', 'headers': ['umac.h'],
     'docstring': docstrings.umac,
     'nonce': 'variable'},
    {'name': 'UMAC96', 'headers': ['umac.h'],
     'docstring': docstrings.umac,
     'nonce': 'variable'},
    {'name': 'UMAC128', 'headers': ['umac.h'],
     'docstring': docstrings.umac,
     'nonce': 'variable'},
    {'name': 'Poly1305_AES', 'headers': ['poly1305.h'],
     'docstring': docstrings.poly1305,
     'nonce': 'fixed'},
]

random: list[RandomParam] = [
    {'name': 'Yarrow256', 'headers': ['yarrow.h'],
     'docstring': docstrings.yarrow,
     'seedfunc': True,
     'seedsize': 'YARROW256_SEED_FILE_SIZE'},
    {'name': 'DRBG_CTR_AES256', 'headers': ['drbg-ctr.h'],
     'docstring': docstrings.drbg_ctr,
     'seedsize': 'DRBG_CTR_AES256_SEED_SIZE'},
]

exceptions: list[ExceptionParam] = [
    {'name': 'BaseException', 'base': 'NULL',
     'docstring': 'Generic Nettle Exception'},
    {'name': 'KeyLenError', 'base': 'BaseException',
     'docstring': 'Key Length is not as expected'},
    {'name': 'DataLenError', 'base': 'BaseException',
     'docstring': 'Data length is not a multiple of the block size'},
    {'name': 'LenMismatch', 'base': 'BaseException',
     'docstring': 'Data length is not as specified earlier'},
    {'name': 'NotInitializedError', 'base': 'BaseException',
     'docstring': 'Object must be initialized before calling this method'},
    {'name': 'RandomError', 'base': 'BaseException',
     'docstring': 'Failed to open/read /dev/random'},
    {'name': 'RSAError', 'base': 'BaseException',
     'docstring': 'RSA operation failed'},
    {'name': 'ASN1Error', 'base': 'BaseException',
     'docstring': 'ASN1 parsing failed'},
    {'name': 'AuthenticationError', 'base': 'BaseException',
     'docstring': 'Authentication failed'},
]
