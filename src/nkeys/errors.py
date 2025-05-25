# see: https://github.com/nats-io/nkeys/blob/main/errors.go

__all__ = [
    "NKeysError",
    "ErrInvalidPrefixByte",
    "ErrInvalidKey",
    "ErrInvalidPublicKey",
    "ErrInvalidPrivateKey",
    "ErrInvalidSeedLen",
    "ErrInvalidSeed",
    "ErrInvalidEncoding",
    "ErrInvalidSignature",
    "ErrCannotSign",
    "ErrPublicKeyOnly",
    "ErrIncompatibleKey",
    "ErrInvalidChecksum",
    "ErrNoSeedFound",
    "ErrInvalidNkeySeed",
    "ErrInvalidUserSeed",
    "ErrInvalidRecipient",
    "ErrInvalidSender",
    "ErrInvalidCurveKey",
    "ErrInvalidCurveSeed",
    "ErrInvalidEncrypted",
    "ErrInvalidEncVersion",
    "ErrCouldNotDecrypt",
    "ErrInvalidCurveKeyOperation",
    "ErrInvalidNKeyOperation",
    "ErrCannotOpen",
    "ErrCannotSeal",
]


class NKeysError(Exception):
    """Base exception for nkeys-related errors."""


class ErrInvalidPrefixByte(NKeysError):
    """nkeys: invalid prefix byte"""


class ErrInvalidKey(NKeysError):
    """nkeys: invalid key"""


class ErrInvalidPublicKey(NKeysError):
    """nkeys: invalid public key"""


class ErrInvalidPrivateKey(NKeysError):
    """nkeys: invalid private key"""


class ErrInvalidSeedLen(NKeysError):
    """nkeys: invalid seed length"""


class ErrInvalidSeed(NKeysError):
    """nkeys: invalid seed"""


class ErrInvalidEncoding(NKeysError):
    """nkeys: invalid encoded key"""


class ErrInvalidSignature(NKeysError):
    """nkeys: signature verification failed"""


class ErrCannotSign(NKeysError):
    """nkeys: can not sign, no private key available"""


class ErrPublicKeyOnly(NKeysError):
    """nkeys: no seed or private key available"""


class ErrIncompatibleKey(NKeysError):
    """nkeys: incompatible key"""


class ErrInvalidChecksum(NKeysError):
    """nkeys: invalid checksum"""


class ErrNoSeedFound(NKeysError):
    """nkeys: no nkey seed found"""


class ErrInvalidNkeySeed(NKeysError):
    """nkeys: doesn't contain a seed nkey"""


class ErrInvalidUserSeed(NKeysError):
    """nkeys: doesn't contain an user seed nkey"""


class ErrInvalidRecipient(NKeysError):
    """nkeys: not a valid recipient public curve key"""


class ErrInvalidSender(NKeysError):
    """nkeys: not a valid sender public curve key"""


class ErrInvalidCurveKey(NKeysError):
    """nkeys: not a valid curve key"""


class ErrInvalidCurveSeed(NKeysError):
    """nkeys: not a valid curve seed"""


class ErrInvalidEncrypted(NKeysError):
    """nkeys: encrypted input is not valid"""


class ErrInvalidEncVersion(NKeysError):
    """nkeys: encrypted input wrong version"""


class ErrCouldNotDecrypt(NKeysError):
    """nkeys: could not decrypt input"""


class ErrInvalidCurveKeyOperation(NKeysError):
    """nkeys: curve key is not valid for sign/verify"""


class ErrInvalidNKeyOperation(NKeysError):
    """nkeys: only curve key can seal/open"""


class ErrCannotOpen(NKeysError):
    """nkeys: cannot open no private curve key available"""


class ErrCannotSeal(NKeysError):
    """nkeys: cannot seal no private curve key available"""
