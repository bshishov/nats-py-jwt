# see: https://github.com/nats-io/nkeys/blob/main/keypair.go

from typing import Callable, Union, Tuple

import nacl.signing
import nacl.exceptions
import nacl.public
import nacl.utils
import nacl.bindings

from nkeys.common import KeyPair, PrefixByte
from nkeys import errors
from nkeys.strkey import encode_seed, decode_seed, encode
from nkeys.xkeys import create_curve_keys_with_rand

__all__ = ["SEED_LEN", "SeedKeyPair", "create_pair", "create_pair_with_rand"]

SEED_LEN = 32  # All seeds are 32 bytes long


class SeedKeyPair(KeyPair):
    __slots__ = "_encoded_seed"

    def __init__(self, encoded_seed: bytes) -> None:
        self._encoded_seed = encoded_seed

    def seed(self) -> bytes:
        return self._encoded_seed

    def public_key(self) -> str:
        public_prefix, raw = decode_seed(self._encoded_seed)
        pub, _ = nacl.bindings.crypto_sign_seed_keypair(raw)
        pk = encode(public_prefix, pub)
        return pk.decode("ascii")

    def private_key(self) -> bytes:
        _, private = _keys(self)
        return encode(PrefixByte.Private, private)

    def sign(self, data: bytes) -> bytes:
        _, private = _keys(self)
        raw_signed = nacl.bindings.crypto_sign(data, private)
        signature = raw_signed[: nacl.bindings.crypto_sign_BYTES]
        return signature

    def verify(self, data: bytes, sig: bytes) -> bool:
        public, _ = _keys(self)
        verify_key = nacl.signing.VerifyKey(public)
        try:
            verify_key.verify(data, sig)
            return True
        except nacl.signing.exc.BadSignatureError:
            return False

    def wipe(self) -> None:
        self._encoded_seed = b""

    def seal(self, data: bytes, recipient: str) -> bytes:
        raise errors.ErrInvalidNKeyOperation

    def seal_with_rand(
        self, data: bytes, recipient: str, rand: Callable[[int], bytes]
    ) -> bytes:
        raise errors.ErrInvalidNKeyOperation

    def open(self, data: Union[bytes, memoryview], sender: str) -> bytes:
        raise errors.ErrInvalidNKeyOperation


def create_pair(prefix: PrefixByte) -> KeyPair:
    # will create a KeyPair based on the rand entropy and a type/prefix byte
    return create_pair_with_rand(prefix, nacl.utils.random)


def create_pair_with_rand(prefix: PrefixByte, rand: Callable[[int], bytes]) -> KeyPair:
    # will create a KeyPair based on the rand reader and a type/prefix byte. rand can be nil.
    if prefix == PrefixByte.Curve:
        return create_curve_keys_with_rand(rand)

    key = nacl.signing.SigningKey(rand(SEED_LEN))
    private = bytes(key)

    seed = encode_seed(prefix, private)
    return SeedKeyPair(seed)


def _raw_seed(kp: SeedKeyPair) -> bytes:
    # rawSeed will return the raw, decoded 64 byte seed.
    _, raw = decode_seed(kp.seed())
    return raw


def _keys(kp: SeedKeyPair) -> Tuple[bytes, bytes]:
    raw = _raw_seed(kp)
    public, private = nacl.bindings.crypto_sign_seed_keypair(raw)
    return public, private
