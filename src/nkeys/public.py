# see: https://github.com/nats-io/nkeys/blob/main/public.go

from typing import Union, Callable

import nacl.signing
import nacl.utils

from nkeys import errors
from nkeys.common import KeyPair, PrefixByte
from nkeys.strkey import encode

__all__ = ["PublicKey"]


class PublicKey(KeyPair):
    """A KeyPair from a public key capable of verifying only."""

    __slots__ = "_prefix", "_public_key"

    def __init__(self, prefix: PrefixByte, public_key: bytes):
        self._prefix = prefix
        self._public_key = public_key

    def seed(self) -> bytes:
        """will return an error since this is not available for public key only KeyPairs."""
        raise errors.ErrPublicKeyOnly

    def public_key(self) -> str:
        """will return the encoded public key associated with the KeyPair. All KeyPairs have a public key."""
        public_key = encode(self._prefix, self._public_key)
        return public_key.decode("ascii")

    def private_key(self) -> bytes:
        """will return an error since this is not available for public key only KeyPairs."""
        raise errors.ErrPublicKeyOnly

    def sign(self, data: bytes) -> bytes:
        """will return an error since this is not available for public key only KeyPairs."""
        raise errors.ErrCannotSign

    def verify(self, data: bytes, sig: bytes) -> bool:
        """will verify the input against a signature utilizing the public key."""
        verify_key = nacl.signing.VerifyKey(self._public_key)
        try:
            verify_key.verify(data, sig)
            return True
        except nacl.signing.exc.BadSignatureError:
            return False

    def wipe(self) -> None:
        """Wipe will randomize the public key and erase the pre byte."""
        self._prefix = PrefixByte(0)
        self._public_key = nacl.utils.random(len(self._public_key))

    def seal(self, data: bytes, recipient: str) -> bytes:
        if self._prefix == PrefixByte.Curve:
            raise errors.ErrCannotSeal
        raise errors.ErrInvalidNKeyOperation

    def seal_with_rand(
        self, data: bytes, recipient: str, rand: Callable[[int], bytes]
    ) -> bytes:
        if self._prefix == PrefixByte.Curve:
            raise errors.ErrCannotSeal
        raise errors.ErrInvalidNKeyOperation

    def open(self, data: Union[bytes, memoryview], sender: str) -> bytes:
        if self._prefix == PrefixByte.Curve:
            raise errors.ErrCannotOpen
        raise errors.ErrInvalidNKeyOperation
