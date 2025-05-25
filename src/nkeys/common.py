# See: https://github.com/nats-io/nkeys/blob/main/nkeys.go

from typing import Callable, Union
from abc import abstractmethod, ABCMeta
from enum import IntEnum


__version__ = "0.4.7"


__all__ = ["KeyPair", "PrefixByte", "prefix_to_str", "SEED_LEN"]

SEED_LEN = 32


class PrefixByte(IntEnum):
    # PrefixByteSeed is the version byte used for encoded NATS Seeds
    Seed = 18 << 3  # Base32-encodes to "S..."

    # PrefixBytePrivate is the version byte used for encoded NATS Private keys
    Private = 15 << 3  # Base32-encodes to 'P...'

    # PrefixByteServer is the version byte used for encoded NATS Servers
    Server = 13 << 3  # Base32-encodes to 'N...'

    # PrefixByteCluster is the version byte used for encoded NATS Clusters
    Cluster = 2 << 3  # Base32-encodes to 'C...'

    # PrefixByteOperator is the version byte used for encoded NATS Operators
    Operator = 14 << 3  # Base32-encodes to 'O...'

    # PrefixByteAccount is the version byte used for encoded NATS Accounts
    Account = 0  # Base32-encodes to 'A...'

    # PrefixByteUser is the version byte used for encoded NATS Users
    User = 20 << 3  # Base32-encodes to 'U...'

    # PrefixByteCurve is the version byte used for encoded CurveKeys (X25519)
    Curve = 23 << 3  # Base32-encodes to 'X...'

    # PrefixByteUnknown is for unknown prefixes.
    Unknown = 25 << 3  # Base32-encodes to 'Z...'

    def __str__(self) -> str:
        return prefix_to_str(self)


_PREFIX_NAMES = {
    PrefixByte.Operator: "operator",
    PrefixByte.Server: "server",
    PrefixByte.Cluster: "cluster",
    PrefixByte.Account: "account",
    PrefixByte.User: "user",
    PrefixByte.Seed: "seed",
    PrefixByte.Private: "private",
    PrefixByte.Curve: "x25519",
}


def prefix_to_str(p: PrefixByte) -> str:
    return _PREFIX_NAMES.get(p, "unknown")


class KeyPair(metaclass=ABCMeta):
    @abstractmethod
    def seed(self) -> bytes:
        raise NotImplementedError

    @abstractmethod
    def public_key(self) -> str:
        raise NotImplementedError

    @abstractmethod
    def private_key(self) -> bytes:
        raise NotImplementedError

    @abstractmethod
    def sign(self, data: bytes) -> bytes:
        # Sign is only supported on Non CurveKeyPairs
        raise NotImplementedError

    @abstractmethod
    def verify(self, data: bytes, sig: bytes) -> bool:
        # Verify is only supported on Non CurveKeyPairs
        raise NotImplementedError

    @abstractmethod
    def wipe(self) -> None:
        raise NotImplementedError

    @abstractmethod
    def seal(self, data: bytes, recipient: str) -> bytes:
        # Seal is only supported on CurveKeyPair
        raise NotImplementedError

    @abstractmethod
    def seal_with_rand(
        self, data: bytes, recipient: str, rand: Callable[[int], bytes]
    ) -> bytes:
        # SealWithRand is only supported on CurveKeyPair
        raise NotImplementedError

    @abstractmethod
    def open(self, data: Union[bytes, memoryview], sender: str) -> bytes:
        # Open is only supported on CurveKey
        raise NotImplementedError
