import pytest

import nacl.utils

from nkeys import from_public_key
from nkeys.common import PrefixByte, KeyPair
from nkeys.xkeys import (
    create_curve_keys,
    create_curve_keys_with_rand,
    from_curve_seed,
    CURVE_KEY_LEN,
)
from nkeys.errors import (
    ErrInvalidCurveKeyOperation,
    ErrCannotOpen,
    ErrCannotSeal,
    NKeysError,
)
from nkeys.strkey import encode


def test_curve_from_create_curve_keys() -> None:
    kp = create_curve_keys()
    _test_curve(kp)


def test_curve_from_create_pair() -> None:
    kp = create_curve_keys_with_rand(nacl.utils.random)
    _test_curve(kp)


def test_curve_from_seed() -> None:
    kp: KeyPair = create_curve_keys()
    seed: bytes = kp.seed()

    nkp: KeyPair = from_curve_seed(seed)
    assert isinstance(nkp, type(kp))
    _test_curve(nkp)


def test_curve_from_key_pair() -> None:
    kp: KeyPair = create_curve_keys()
    with pytest.raises(ErrInvalidCurveKeyOperation):
        kp.sign(b"hello")

    with pytest.raises(ErrInvalidCurveKeyOperation):
        kp.verify(b"hello", b"bad")


def test_curve_public() -> None:
    kp: KeyPair = create_curve_keys()
    with pytest.raises(ErrInvalidCurveKeyOperation):
        kp.sign(b"hello")

    pk = kp.public_key()
    pub = from_public_key(pk)

    with pytest.raises(ErrCannotOpen):
        pub.open(b"hello", "bad")

    with pytest.raises(ErrCannotSeal):
        pub.seal(b"hello", "bad")

    with pytest.raises(ErrCannotSeal):
        pub.seal_with_rand(b"hello", "bad", nacl.utils.random)


def test_curve_public_empty_bug() -> None:
    kp: KeyPair = create_curve_keys()
    pub: str = kp.public_key()

    rkp: KeyPair = create_curve_keys()
    rpub: str = rkp.public_key()

    msg: bytes = b"Empty public better not work!"
    encrypted: bytes = kp.seal(msg, rpub)

    decrypted: bytes = rkp.open(encrypted, pub)
    assert decrypted == msg

    # Check with empty pub key
    empty: bytes = bytes(CURVE_KEY_LEN)
    epub: bytes = encode(PrefixByte.Curve, empty)

    with pytest.raises(NKeysError):
        rkp.open(encrypted, epub.decode("ascii"))


def _test_curve(kp: KeyPair) -> None:
    # Check seed
    seed: bytes = kp.seed()
    assert seed is not None

    # Check public key
    pub: str = kp.public_key()
    assert pub[0] == "X"

    # Check private key
    private: str = kp.private_key().decode("ascii")
    assert private[0] == "P"

    # Test sealing and opening
    rkp: KeyPair = create_curve_keys()
    rpub: str = rkp.public_key()

    msg: bytes = b"Hello xkeys!"
    encrypted: bytes = kp.seal(msg, rpub)

    decrypted: bytes = rkp.open(encrypted, pub)
    assert decrypted == msg
