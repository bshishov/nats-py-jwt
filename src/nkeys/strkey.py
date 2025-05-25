# see: https://github.com/nats-io/nkeys/blob/main/strkey.go

from typing import Union, Tuple
import base64
import binascii
from io import BytesIO

from nkeys import errors, crc16
from nkeys.common import KeyPair, PrefixByte, SEED_LEN


__all__ = [
    "encode",
    "encode_seed",
    "is_valid_encoding",
    "decode",
    "decode_seed",
    "prefix_from_input",
    "is_valid_public_key",
    "is_valid_public_user_key",
    "is_valid_public_account_key",
    "is_valid_public_server_key",
    "is_valid_public_cluster_key",
    "is_valid_public_operator_key",
    "is_valid_public_curve_key",
    "prefix_byte",
    "compatible_key_pair",
    "decode_pub_curve_key",
]


def _b32encode_no_padding(data: Union[memoryview, bytes, str]) -> bytes:
    # No padding "="

    if isinstance(data, str):
        data = data.encode("ascii")

    try:
        return base64.b32encode(data).rstrip(b"=")  # no padding
    except binascii.Error:
        raise errors.ErrInvalidEncoding


def _b32decode_no_padding(data: Union[memoryview, bytes, str]) -> bytes:
    # Data might miss the padding "="
    if isinstance(data, str):
        data = data.encode("ascii")

    pad = -len(data) % 8
    if pad == 0:
        try:
            return base64.b32decode(data)
        except binascii.Error:
            raise errors.ErrInvalidEncoding

    buffer = bytearray(data)
    buffer += b"=" * pad

    try:
        return base64.b32decode(buffer)
    except binascii.Error:
        raise errors.ErrInvalidEncoding


def encode(prefix: PrefixByte, src: Union[memoryview, bytes]) -> bytes:
    # encode will encode a raw key or seed with the prefix and crc16 and then base32 encoded.
    if not check_valid_prefix_byte(prefix):
        raise errors.ErrInvalidPrefixByte

    buffer = BytesIO()
    buffer.write(b"%c" % prefix.value)
    buffer.write(src)

    # Calculate and write CRC16
    checksum = crc16.crc16(buffer.getbuffer())
    buffer.write(checksum)

    return _b32encode_no_padding(buffer.getbuffer())


def encode_seed(public: PrefixByte, src: Union[memoryview, bytes]) -> bytes:
    # EncodeSeed will encode a raw key with the prefix and then seed prefix and crc16 and then base32 encoded.
    # `src` must be 32 bytes long (ed25519.SeedSize).
    if not check_valid_public_prefix_byte(public):
        raise errors.ErrInvalidPrefixByte

    if len(src) != SEED_LEN:
        raise errors.ErrInvalidSeedLen

    # In order to make this human printable for both bytes, we need to do a little
    # bit manipulation to set up for base32 encoding which takes 5 bits at a time.
    b1 = PrefixByte.Seed.value | (public.value >> 5)
    b2 = (public.value & 31) << 3  # 31 = 00011111

    buffer = BytesIO()
    buffer.write(b"%c%c" % (b1, b2))

    # write payload
    buffer.write(src)

    # Calculate and write CRC16
    checksum = crc16.crc16(buffer.getbuffer())
    buffer.write(checksum)

    return _b32encode_no_padding(buffer.getbuffer())


def is_valid_encoding(src: memoryview) -> bool:
    try:
        _decode(src)
        return True
    except errors.NKeysError:
        return False


def _decode(src: Union[memoryview, bytes, str]) -> memoryview:
    decoded = _b32decode_no_padding(src)
    if len(decoded) < 4:
        raise errors.ErrInvalidEncoding

    view = memoryview(decoded)
    payload = view[:-2]
    crc = view[-2:]
    if not crc16.validate(payload, crc):
        raise errors.ErrInvalidChecksum
    return payload


def decode(expected_prefix: PrefixByte, src: Union[memoryview, bytes]) -> bytes:
    # decode_with_prefix will decode the base32 string and check crc16 and enforce the prefix is what is expected.
    if not check_valid_prefix_byte(expected_prefix):
        raise errors.ErrInvalidPrefixByte
    raw = _decode(src)
    b1 = raw[0] & 248  # 248 = 11111000
    if prefix_byte(b1) != expected_prefix:
        raise errors.ErrInvalidPrefixByte
    return raw[1:].tobytes()


def decode_seed(src: Union[memoryview, bytes]) -> Tuple[PrefixByte, bytes]:
    raw = _decode(src)
    b1 = raw[0] & 248  # 248 = 11111000
    b2 = (raw[0] & 7) << 5 | ((raw[1] & 248) >> 3)  # 7 = 00000111

    if b1 != PrefixByte.Seed.value:
        raise errors.ErrInvalidSeed

    public_prefix_byte = prefix_byte(b2)
    if not check_valid_public_prefix_byte(public_prefix_byte):
        raise errors.ErrInvalidSeed

    return public_prefix_byte, raw[2:].tobytes()


def prefix_from_input(src: Union[memoryview, bytes]) -> PrefixByte:
    # Prefix returns PrefixBytes of its input
    try:
        b = _decode(src)
    except errors.NKeysError:
        return PrefixByte.Unknown

    try:
        return prefix_byte(b[0])
    except errors.ErrInvalidPrefixByte:
        pass

    # might be a seed
    if b[0] & 248 == PrefixByte.Seed.value:
        return PrefixByte.Seed

    return PrefixByte.Unknown


def is_valid_public_key(src: Union[memoryview, bytes]) -> bool:
    prefix = prefix_from_input(src)  # guesses prefix from input (also decoding)
    return check_valid_public_prefix_byte(prefix)


def is_valid_public_user_key(src: Union[memoryview, bytes]) -> bool:
    # will decode and verify the string is a valid encoded Public User Key.
    try:
        decode(PrefixByte.User, src)
        return True
    except errors.NKeysError:
        return False


def is_valid_public_account_key(src: Union[memoryview, bytes]) -> bool:
    # will decode and verify the string is a valid encoded Public Account Key.
    try:
        decode(PrefixByte.Account, src)
        return True
    except errors.NKeysError:
        return False


def is_valid_public_server_key(src: Union[memoryview, bytes]) -> bool:
    # will decode and verify the string is a valid encoded Public Server Key.
    try:
        decode(PrefixByte.Server, src)
        return True
    except errors.NKeysError:
        return False


def is_valid_public_cluster_key(src: Union[memoryview, bytes]) -> bool:
    # will decode and verify the string is a valid encoded Public Cluster Key.
    try:
        decode(PrefixByte.Cluster, src)
        return True
    except errors.NKeysError:
        return False


def is_valid_public_operator_key(src: Union[memoryview, bytes]) -> bool:
    # will decode and verify the string is a valid encoded Public Operator Key.
    try:
        decode(PrefixByte.Operator, src)
        return True
    except errors.NKeysError:
        return False


def is_valid_public_curve_key(src: Union[memoryview, bytes]) -> bool:
    # will decode and verify the string is a valid encoded Public Curve Key.
    try:
        decode(PrefixByte.Curve, src)
        return True
    except errors.NKeysError:
        return False


_VALID_PREFIX_BYTES = {
    PrefixByte.Operator,
    PrefixByte.Server,
    PrefixByte.Cluster,
    PrefixByte.Account,
    PrefixByte.User,
    PrefixByte.Seed,
    PrefixByte.Private,
    PrefixByte.Curve,
}

_VALID_PUBLIC_PREFIX_BYTES = {
    PrefixByte.Operator,
    PrefixByte.Server,
    PrefixByte.Cluster,
    PrefixByte.Account,
    PrefixByte.User,
    PrefixByte.Curve,
}


def check_valid_prefix_byte(prefix: PrefixByte) -> bool:
    # We are assuming that prefix is already parsed
    return prefix in _VALID_PREFIX_BYTES


def check_valid_public_prefix_byte(prefix: PrefixByte) -> bool:
    # We are assuming that prefix is already parsed
    return prefix in _VALID_PUBLIC_PREFIX_BYTES


def prefix_byte(x: int) -> PrefixByte:
    try:
        return PrefixByte(x)
    except (ValueError, TypeError):
        raise errors.ErrInvalidPrefixByte


def compatible_key_pair(kp: KeyPair, *expected: PrefixByte) -> bool:
    pk = kp.public_key()
    try:
        pk_type = prefix_from_input(pk.encode("ascii"))
    except errors.NKeysError:
        return False

    for k in expected:
        if pk_type == k:
            return True
    return False


def decode_pub_curve_key(src: str) -> bytes:
    # see: https://github.com/nats-io/nkeys/blob/main/xkeys.go
    raw = _b32decode_no_padding(src)
    if len(raw) != 35:
        raise errors.ErrInvalidCurveKey

    prefix = prefix_byte(raw[0])
    if prefix != PrefixByte.Curve:
        raise errors.ErrInvalidPublicKey

    view = memoryview(raw)
    payload = view[:-2]
    crc = view[-2:]
    if not crc16.validate(payload, crc):
        raise errors.ErrInvalidChecksum
    return payload[1:].tobytes()  # Copy over, ignore prefix byte.
