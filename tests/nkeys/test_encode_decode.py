from nkeys.common import PrefixByte
from nkeys.strkey import (
    encode_seed,
    decode_seed,
    encode,
    _decode,
    _b32decode_no_padding,
)
from nkeys.crc16 import crc16


def test_encode_checksum() -> None:
    payload = b"hello"
    crc = crc16(b"%c%s" % (PrefixByte.Seed.value, payload))
    encoded = encode(PrefixByte.Seed, payload)
    decoded_with_crc = _b32decode_no_padding(encoded)
    assert decoded_with_crc[-2:] == crc


def test_encode_decode() -> None:
    payload = b"hello"

    encoded = encode(PrefixByte.Seed, payload)
    print(encoded)
    decoded = _decode(encoded)[1:].tobytes()  # skip prefix
    print(decoded)
    assert payload == decoded


def test_encode_decode_seed() -> None:
    seed = b"hello" * 6 + b"xx"  # to match n=32

    encoded = encode_seed(PrefixByte.User, seed)
    p, decoded = decode_seed(encoded)
    assert p == PrefixByte.User
    assert decoded == seed
