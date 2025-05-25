# see: https://github.com/nats-io/nkeys/blob/main/xkeys.go

from typing import Callable, Union

from io import BytesIO

import nacl.signing
import nacl.exceptions
import nacl.public
import nacl.utils
import nacl.bindings

from nkeys import errors
from nkeys.common import KeyPair, PrefixByte
from nkeys.strkey import encode_seed, decode_seed, encode, decode_pub_curve_key


__all__ = [
    "create_curve_keys",
    "create_curve_keys_with_rand",
    "from_curve_seed",
]

CURVE_KEY_LEN = 32
CURVE_DECODE_LEN = 35
CURVE_NONCE_LEN = 24

# Only version for now, but could add in X3DH in the future, etc.
XKEY_VERSION_V1 = b"xkv1"
VLEN = len(XKEY_VERSION_V1)


class _CurveKeyPair(KeyPair):
    __slots__ = "_seed"

    def __init__(self, seed: bytes) -> None:
        if len(seed) != CURVE_KEY_LEN:
            raise errors.ErrInvalidCurveSeed
        self._seed = seed

    def seed(self) -> bytes:
        return encode_seed(PrefixByte.Curve, self._seed)

    def public_key(self) -> str:
        pub = nacl.bindings.crypto_scalarmult_base(self._seed)
        key = encode(PrefixByte.Curve, pub)
        return key.decode("ascii")

    def private_key(self) -> bytes:
        return encode(PrefixByte.Private, self._seed)

    def sign(self, data: bytes) -> bytes:
        raise errors.ErrInvalidCurveKeyOperation

    def verify(self, data: bytes, sig: bytes) -> bool:
        raise errors.ErrInvalidCurveKeyOperation

    def wipe(self) -> None:
        del self._seed

    def seal(self, data: bytes, recipient: str) -> bytes:
        # Seal is compatible with nacl.Box.Seal() and can be used in similar situations for small messages.
        # We generate the nonce from crypto rand by default.
        return self.seal_with_rand(data, recipient, nacl.utils.random)

    def seal_with_rand(
        self, data: bytes, recipient: str, rand: Callable[[int], bytes]
    ) -> bytes:
        try:
            recipient_pub = decode_pub_curve_key(recipient)
        except errors.NKeysError:
            raise errors.ErrInvalidRecipient

        nonce = rand(CURVE_NONCE_LEN)

        buffer = BytesIO()
        buffer.write(XKEY_VERSION_V1)
        buffer.write(nonce)

        try:
            box = nacl.public.Box(
                private_key=nacl.public.PrivateKey(self._seed),
                public_key=nacl.public.PublicKey(recipient_pub),
            )
            encrypted = box.encrypt(data, nonce).ciphertext
        except (nacl.exceptions.CryptoError, nacl.exceptions.RuntimeError):
            raise errors.ErrCannotSeal

        buffer.write(encrypted)
        return buffer.getvalue()

    def open(self, data: Union[bytes, memoryview], sender: str) -> bytes:
        if len(data) <= VLEN + CURVE_NONCE_LEN:
            raise errors.ErrInvalidEncrypted

        if data[:VLEN] != XKEY_VERSION_V1:
            raise errors.ErrInvalidEncVersion

        nonce = data[VLEN : VLEN + CURVE_NONCE_LEN]

        try:
            sender_pub = decode_pub_curve_key(sender)
        except errors.NKeysError:
            raise errors.ErrInvalidSender

        try:
            box = nacl.public.Box(
                private_key=nacl.public.PrivateKey(self._seed),
                public_key=nacl.public.PublicKey(sender_pub),
            )
            decrypted = box.decrypt(data[VLEN + CURVE_NONCE_LEN :], nonce)
        except (nacl.exceptions.CryptoError, nacl.exceptions.RuntimeError):
            raise errors.ErrCouldNotDecrypt
        return decrypted


def create_curve_keys() -> KeyPair:
    return create_curve_keys_with_rand(nacl.utils.random)


def create_curve_keys_with_rand(rand: Callable[[int], bytes]) -> KeyPair:
    key = nacl.signing.SigningKey(rand(CURVE_KEY_LEN))
    return _CurveKeyPair(bytes(key))


def from_curve_seed(seed: bytes) -> KeyPair:
    # Will create a curve key pair from seed.
    pb, raw = decode_seed(seed)
    if pb != PrefixByte.Curve or len(raw) != CURVE_KEY_LEN:
        raise errors.ErrInvalidCurveSeed
    return _CurveKeyPair(raw)
