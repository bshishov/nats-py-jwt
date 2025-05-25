import pytest

import nacl.utils

from nkeys import (
    create_pair,
    PrefixByte,
    errors,
    __version__,
    from_seed,
    from_public_key,
    from_raw_seed,
)
from nkeys.strkey import (
    is_valid_public_key,
    is_valid_public_user_key,
    is_valid_public_account_key,
    is_valid_public_server_key,
    is_valid_public_cluster_key,
    is_valid_public_operator_key,
    compatible_key_pair,
    encode,
    decode,
    encode_seed,
    decode_seed,
    prefix_from_input,
    _decode,
    prefix_byte,
)
from nkeys.keypair import SeedKeyPair, _keys


def test_version() -> None:
    """Test version format"""
    # Semantic versioning
    import re

    version_re = re.compile(r"\d+\.\d+\.\d+(-\S+)?")
    assert (
        version_re.match(__version__) is not None
    ), "Version not compatible with semantic versioning"


def test_encode() -> None:
    """Test encoding functionality"""
    raw_key = nacl.utils.random(32)
    encoded = encode(PrefixByte.User, raw_key)
    assert encoded is not None

    # Test invalid prefix
    with pytest.raises(errors.ErrInvalidPrefixByte):
        encode(PrefixByte.Unknown, raw_key)


def test_decode() -> None:
    """Test decoding functionality"""
    raw_key = nacl.utils.random(32)
    encoded = encode(PrefixByte.User, raw_key)

    decoded = decode(PrefixByte.User, encoded)
    assert decoded == raw_key, "Decoded does not match the original"


def test_seed() -> None:
    """Test seed handling"""
    raw_key_short = nacl.utils.random(16)

    # Test invalid seed length
    with pytest.raises(errors.ErrInvalidSeedLen):
        encode_seed(PrefixByte.User, raw_key_short)

    # Test invalid prefix
    with pytest.raises(errors.ErrInvalidPrefixByte):
        encode_seed(PrefixByte.Seed, raw_key_short)

    raw_seed = nacl.utils.random(32)
    seed = encode_seed(PrefixByte.User, raw_seed)

    prefix, decoded = decode_seed(seed)
    assert prefix == PrefixByte.User, f"Expected PrefixByteUser, got {prefix}"
    assert decoded == raw_seed, "Decoded seed does not match the original"


def test_account() -> None:
    """Test account key pair functionality"""
    account = create_pair(PrefixByte.Account)
    assert account is not None, "Expected a non-nil account"

    seed = account.seed()
    assert seed is not None, "Unexpected error retrieving seed"

    public = account.public_key()
    assert public[0] == "A", f"Expected prefix 'A', got {public[0]}"
    assert is_valid_public_account_key(
        public.encode("ascii")
    ), "Not a valid public account key"

    private = account.private_key().decode("ascii")
    assert private[0] == "P", f"Expected prefix 'P', got {private[0]}"

    data = b"Hello World"
    sig = account.sign(data)
    assert len(sig) == 64, f"Expected signature size of 64, got {len(sig)}"

    assert account.verify(data, sig)


def test_user() -> None:
    """Test user key pair functionality"""
    user = create_pair(PrefixByte.User)
    assert user is not None, "Expected a non-nil user"

    public = user.public_key()
    assert public[0] == "U", f"Expected prefix 'U', got {public[0]}"
    assert is_valid_public_user_key(
        public.encode("ascii")
    ), "Not a valid public user key"


def test_operator() -> None:
    """Test operator key pair functionality"""
    operator = create_pair(PrefixByte.Operator)
    assert operator is not None, "Expected a non-nil operator"

    public = operator.public_key()
    assert public[0] == "O", f"Expected prefix 'O', got {public[0]}"
    assert is_valid_public_operator_key(
        public.encode("ascii")
    ), "Not a valid public operator key"


def test_cluster() -> None:
    """Test cluster key pair functionality"""
    cluster = create_pair(PrefixByte.Cluster)
    assert cluster is not None, "Expected a non-nil cluster"

    public = cluster.public_key()
    assert public[0] == "C", f"Expected prefix 'C', got {public[0]}"
    assert is_valid_public_cluster_key(
        public.encode("ascii")
    ), "Not a valid public cluster key"


def test_server() -> None:
    """Test server key pair functionality"""
    server = create_pair(PrefixByte.Server)
    assert server is not None, "Expected a non-nil server"

    public = server.public_key()
    assert public[0] == "N", f"Expected prefix 'N', got {public[0]}"
    assert is_valid_public_server_key(
        public.encode("ascii")
    ), "Not a valid public server key"


def test_prefix_byte() -> None:
    """Test prefix byte functionality"""
    user = create_pair(PrefixByte.User)
    pub = user.public_key()
    assert (
        prefix_from_input(pub.encode("ascii")) == PrefixByte.User
    ), "Expected PrefixByteUser"

    seed = user.seed()
    assert prefix_from_input(seed) == PrefixByte.Seed, "Expected PrefixByteSeed"

    assert (
        prefix_from_input(b"SEED") == PrefixByte.Unknown
    ), "Expected PrefixByteUnknown"

    account = create_pair(PrefixByte.Account)
    pub = account.public_key()
    assert (
        prefix_from_input(pub.encode("ascii")) == PrefixByte.Account
    ), "Expected PrefixByteAccount"


def test_is_valid_public() -> None:
    """Test public key validation"""
    user = create_pair(PrefixByte.User)
    pub = user.public_key()
    assert is_valid_public_key(
        pub.encode("ascii")
    ), "Expected pub to be a valid public key"

    seed = user.seed()
    assert not is_valid_public_key(seed), "Expected seed to not be a valid public key"

    assert not is_valid_public_key(b"BAD"), "Expected BAD to not be a valid public key"

    account = create_pair(PrefixByte.Account)
    pub = account.public_key()
    assert is_valid_public_key(
        pub.encode("ascii")
    ), "Expected pub to be a valid public key"


def test_from_public() -> None:
    """Test public key pair creation"""
    user = create_pair(PrefixByte.User)
    assert user is not None, "Expected a non-nil user"

    public_key = user.public_key()

    pub_user = from_public_key(public_key)

    public_key2 = pub_user.public_key()
    assert (
        public_key2 == public_key
    ), f"Expected public keys to match: {public_key2} vs {public_key}"

    # Test invalid operations on public key pair
    with pytest.raises(errors.ErrCannotSign):
        pub_user.sign(b"Hello World")

    with pytest.raises(errors.ErrPublicKeyOnly):
        pub_user.seed()

    data = b"Hello World"
    sig = user.sign(data)
    assert pub_user.verify(data, sig)

    user2 = create_pair(PrefixByte.User)
    sig = user2.sign(data)
    assert pub_user.verify(data, sig) is False


def test_from_seed() -> None:
    """Test key pair creation from seed"""
    account = create_pair(PrefixByte.Account)
    assert account is not None, "Expected a non-nil account"

    data = b"Hello World"
    sig = account.sign(data)

    seed = account.seed()
    assert seed.startswith(b"SA"), f"Expected seed to start with 'SA', got {seed[:2]!r}"

    account2 = from_seed(seed)
    assert account2 is not None, "Expected a non-nil account"

    assert account2.verify(data, sig)


def test_key_pair_failures() -> None:
    """Test key pair creation failures"""
    # Test insufficient random
    with pytest.raises(errors.ErrInvalidSeedLen):
        encode_seed(PrefixByte.User, b"too short")

    # Test invalid prefix
    with pytest.raises(errors.ErrInvalidPrefixByte):
        create_pair(PrefixByte.Private)

    # Test invalid seed decoding
    kp = SeedKeyPair(b"SEEDBAD")

    with pytest.raises(errors.NKeysError):
        _keys(kp)

    with pytest.raises(errors.NKeysError):
        kp.public_key()

    with pytest.raises(errors.NKeysError):
        kp.private_key()

    with pytest.raises(errors.NKeysError):
        kp.sign(b"ok")


def test_bad_decode() -> None:
    """Test invalid decoding cases"""
    with pytest.raises(errors.NKeysError):
        _decode(b"foo!")

    with pytest.raises(errors.NKeysError):
        _decode(b"OK")

    # Create invalid checksum
    account = create_pair(PrefixByte.Account)
    pkey = account.public_key()
    bpkey = bytearray(pkey.encode("ascii"))
    bpkey[-1] = ord("0")
    bpkey[-2] = ord("0")
    with pytest.raises(errors.NKeysError):
        _decode(bpkey)

    with pytest.raises(errors.NKeysError):
        decode(PrefixByte.User, bpkey)

    with pytest.raises(errors.NKeysError):
        decode(prefix_byte(3 << 3), bpkey)

    with pytest.raises(errors.NKeysError):
        decode(PrefixByte.Account, bpkey)

    # Seed version
    with pytest.raises(errors.NKeysError):
        decode_seed(bpkey)

    with pytest.raises(errors.NKeysError):
        decode_seed(pkey.encode("ascii"))

    seed = account.seed()
    bseed = bytearray(seed)
    bseed[1] = ord("S")
    with pytest.raises(errors.NKeysError):
        decode_seed(bseed)

    with pytest.raises(errors.NKeysError):
        from_seed(bseed)

    with pytest.raises(errors.NKeysError):
        from_public_key(bpkey)

    with pytest.raises(errors.NKeysError):
        from_public_key(seed)


def test_from_raw_seed() -> None:
    """Test key pair creation from raw seed"""
    user = create_pair(PrefixByte.User)
    se = user.seed()
    _, raw = decode_seed(se)
    user2 = from_raw_seed(PrefixByte.User, raw)
    s2e = user2.seed()
    assert se == s2e, f"Expected seeds to match"


def test_wipe() -> None:
    """Test key pair memory wiping"""
    user = create_pair(PrefixByte.User)
    pub_key = user.public_key()

    seed = user.seed()
    copy = bytearray(seed)
    user.wipe()
    assert not user.seed(), "Expected seed to be empty after wipe"
    # TODO: is is possible to fix copy of immutable bytes? move to bytearray/memory?
    # assert seed != copy, "Expected memory to be randomized after wipe"

    # Test public key pair wiping
    user = from_public_key(pub_key)

    ed_pub = getattr(user, "_public_key")
    copy = bytearray(ed_pub)
    user.wipe()
    assert getattr(user, "_prefix") == PrefixByte(0), "Expected prefix to be changed"
    # TODO: is is possible to fix copy of immutable bytes? move to bytearray/memory?
    # assert ed_pub != copy, "Expected memory to be randomized after wipe"


def test_validate_key_pair_role() -> None:
    """Test key pair role validation"""
    okp = create_pair(PrefixByte.Operator)
    akp = create_pair(PrefixByte.Account)
    ukp = create_pair(PrefixByte.User)
    ckp = create_pair(PrefixByte.Cluster)
    skp = create_pair(PrefixByte.Server)

    key_roles = [
        (okp, [PrefixByte.Operator], True, "want operator"),
        (akp, [PrefixByte.Account], True, "want account"),
        (ukp, [PrefixByte.User], True, "want user"),
        (ckp, [PrefixByte.Cluster], True, "want cluster"),
        (skp, [PrefixByte.Server], True, "want server"),
        (
            okp,
            [PrefixByte.Operator, PrefixByte.Account],
            True,
            "want account or operator",
        ),
        (
            akp,
            [PrefixByte.Operator, PrefixByte.Account],
            True,
            "want account or operator",
        ),
        (akp, [PrefixByte.Operator], False, "want operator got account"),
        (
            ukp,
            [PrefixByte.Operator, PrefixByte.Account],
            False,
            "want account or operator got user",
        ),
    ]

    for kp, roles, expected, name in key_roles:
        is_compatible = compatible_key_pair(kp, *roles)
        assert is_compatible == expected, name


def test_seal_open() -> None:
    """Test seal/open operations"""
    for prefix in [PrefixByte.Operator, PrefixByte.Account, PrefixByte.User]:
        kp = create_pair(prefix)
        assert kp is not None, f"Failed to create pair for {prefix} - nil keypair"

        with pytest.raises(errors.ErrInvalidNKeyOperation):
            kp.open(b"hello", "ME")

        with pytest.raises(errors.ErrInvalidNKeyOperation):
            kp.seal(b"hello", "ME")

        with pytest.raises(errors.ErrInvalidNKeyOperation):
            kp.seal_with_rand(b"hello", "ME", nacl.utils.random)
