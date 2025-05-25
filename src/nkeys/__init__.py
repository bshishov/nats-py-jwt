# See: https://github.com/nats-io/nkeys/blob/main/nkeys.go

from typing import Union

from nkeys import errors
from nkeys.common import KeyPair, PrefixByte
from nkeys.public import PublicKey
from nkeys.strkey import (
    _decode,
    check_valid_public_prefix_byte,
    prefix_byte,
    decode_seed,
    encode_seed,
    is_valid_public_curve_key,
    is_valid_public_operator_key,
    is_valid_public_account_key,
    is_valid_public_user_key,
    is_valid_public_key,
    is_valid_encoding,
    is_valid_public_cluster_key,
    is_valid_public_server_key,
    check_valid_prefix_byte,
)
from nkeys.xkeys import from_curve_seed
from nkeys.keypair import SeedKeyPair, create_pair

__all__ = [
    "KeyPair",
    "PrefixByte",
    "create_user",
    "create_account",
    "create_server",
    "create_cluster",
    "create_operator",
    "from_public_key",
    "from_seed",
    "from_raw_seed",
    "from_curve_seed",
    "create_pair",
    "is_valid_public_curve_key",
    "is_valid_public_operator_key",
    "is_valid_public_account_key",
    "is_valid_public_user_key",
    "is_valid_public_key",
    "is_valid_encoding",
    "is_valid_public_cluster_key",
    "is_valid_public_server_key",
    "check_valid_prefix_byte",
    "check_valid_public_prefix_byte",
]

__version__ = "0.4.7"


def create_user() -> KeyPair:
    return create_pair(PrefixByte.User)


def create_account() -> KeyPair:
    return create_pair(PrefixByte.Account)


def create_server() -> KeyPair:
    return create_pair(PrefixByte.Server)


def create_cluster() -> KeyPair:
    return create_pair(PrefixByte.Cluster)


def create_operator() -> KeyPair:
    return create_pair(PrefixByte.Operator)


def from_public_key(public_key: Union[str, memoryview, bytes]) -> KeyPair:
    raw = _decode(public_key)
    pre = prefix_byte(raw[0])
    if not check_valid_public_prefix_byte(pre):
        raise errors.ErrInvalidPublicKey
    return PublicKey(pre, raw[1:].tobytes())


def from_seed(seed: Union[bytes, memoryview]) -> KeyPair:
    # FromSeed will create a KeyPair capable of signing and verifying signatures.
    prefix, _ = decode_seed(seed)
    if prefix == PrefixByte.Curve:
        return from_curve_seed(seed)
    return SeedKeyPair(seed)


def from_raw_seed(prefix: PrefixByte, raw_seed: Union[bytes, memoryview]) -> KeyPair:
    seed = encode_seed(prefix, raw_seed)
    return SeedKeyPair(seed)
