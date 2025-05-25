import pytest

import nkeys

from natspyjwt import jwt as natsjwt
from natspyjwt.serialization import deserialize_json
from natspyjwt.models import JwtHeader, OperatorClaims, Import, Export, ExportType
from natspyjwt.errors import JwtError


def test_encode_operator_claims() -> None:
    okp = nkeys.create_pair(nkeys.PrefixByte.Operator)
    opk = okp.public_key()

    oc = natsjwt.new_operator_claims(opk)
    oc.name = "O"

    oskp = nkeys.create_pair(nkeys.PrefixByte.Operator)
    ospk = oskp.public_key()

    oc.nats.signing_keys = [ospk]

    # encode and ensure is ascii
    jwt = natsjwt.encode_operator_claims(oc, okp).decode("ascii")
    assert jwt

    # verify parts
    parts = jwt.split(".")
    assert len(parts) == 3

    # verify header
    header_json = natsjwt.decode_b64url_no_padding(parts[0])
    header = deserialize_json(header_json, JwtHeader)
    assert header.typ == "JWT"
    assert header.alg == "ed25519-nkey"

    # verify payload
    payload_json = natsjwt.decode_b64url_no_padding(parts[1])
    payload = deserialize_json(payload_json, OperatorClaims)
    assert payload.name == "O"
    assert payload.sub == opk
    assert payload.iss == opk
    assert payload.nats.signing_keys
    assert ospk in payload.nats.signing_keys
    assert payload.nats.type == "operator"
    assert payload.nats.version == 2

    # verify signature
    assert parts[2]

    # verify the JWT can be decoded and validated
    decoded_claims = natsjwt.decode_claims(jwt.encode("ascii"), OperatorClaims)
    assert decoded_claims
    assert decoded_claims.nats.type == natsjwt.OPERATOR_CLAIM
    assert oc.name == decoded_claims.name
    assert oc.sub == decoded_claims.sub
    assert oc.nats.signing_keys == decoded_claims.nats.signing_keys


def test_encode_account_claims() -> None:
    akp = nkeys.create_pair(nkeys.PrefixByte.Account)
    apk = akp.public_key()

    ac = natsjwt.new_account_claims(apk)
    ac.name = "A"

    ac.nats.imports = [Import(name="Import1", subject="import.subject")]
    ac.nats.exports = [Export(name="Export1", subject="export.subject")]

    # encode and ensure is ascii
    jwt = natsjwt.encode_account_claims(ac, akp).decode("ascii")
    assert jwt

    # verify parts
    parts = jwt.split(".")
    assert len(parts) == 3

    # verify header
    header_json = natsjwt.decode_b64url_no_padding(parts[0])
    header = deserialize_json(header_json, JwtHeader)
    assert header.typ == "JWT"
    assert header.alg == "ed25519-nkey"

    # verify payload
    payload_json = natsjwt.decode_b64url_no_padding(parts[1])
    payload = deserialize_json(payload_json, natsjwt.AccountClaims)
    assert payload.name == "A"
    assert payload.sub == apk
    assert payload.iss == apk
    assert payload.nats.imports
    assert payload.nats.exports
    assert len(payload.nats.imports) == 1
    assert len(payload.nats.exports) == 1
    assert payload.nats.type == "account"
    assert payload.nats.version == 2

    # verify signature
    assert parts[2]

    # verify the JWT can be decoded and validated
    decoded_claims = natsjwt.decode_claims(jwt.encode("ascii"), natsjwt.AccountClaims)
    assert decoded_claims
    assert decoded_claims.name == ac.name
    assert decoded_claims.sub == ac.sub
    assert decoded_claims.nats.imports
    assert decoded_claims.nats.exports
    assert len(decoded_claims.nats.imports) == len(ac.nats.imports)
    assert len(decoded_claims.nats.exports) == len(ac.nats.exports)


def test_encode_user_claims() -> None:
    akp = nkeys.create_pair(nkeys.PrefixByte.Account)
    apk = akp.public_key()

    uc = natsjwt.new_user_claims(apk)
    uc.name = "U"

    uc.nats.pub.allow = ["allow.>"]
    uc.nats.sub.allow = ["subscribe.>"]

    # encode and ensure is ascii
    jwt = natsjwt.encode_user_claims(uc, akp).decode("ascii")
    assert jwt

    # verify parts
    parts = jwt.split(".")
    assert len(parts) == 3

    # verify header
    header_json = natsjwt.decode_b64url_no_padding(parts[0])
    header = deserialize_json(header_json, JwtHeader)
    assert header.typ == "JWT"
    assert header.alg == "ed25519-nkey"

    # verify payload
    payload_json = natsjwt.decode_b64url_no_padding(parts[1])
    payload = deserialize_json(payload_json, natsjwt.UserClaims)
    assert payload.name == "U"
    assert payload.sub == apk
    assert payload.iss == apk
    assert payload.nats.pub.allow
    assert "allow.>" in payload.nats.pub.allow
    assert payload.nats.sub.allow
    assert "subscribe.>" in payload.nats.sub.allow
    assert payload.nats.type == "user"
    assert payload.nats.version == 2

    # verify signature
    assert parts[2]

    # verify the JWT can be decoded and validated
    decoded_claims = natsjwt.decode_claims(jwt.encode("ascii"), natsjwt.UserClaims)
    assert decoded_claims
    assert decoded_claims.name == uc.name
    assert decoded_claims.sub == uc.sub
    assert decoded_claims.nats.pub.allow == uc.nats.pub.allow
    assert decoded_claims.nats.sub.allow == uc.nats.sub.allow


def test_encode_activation_claims() -> None:
    akp = nkeys.create_pair(nkeys.PrefixByte.Account)
    apk = akp.public_key()

    ac = natsjwt.new_activation_claims(apk)
    ac.name = "Activation"

    ac.nats.subject = "import.subject"
    ac.nats.kind = 1

    # encode and ensure is ascii
    jwt = natsjwt.encode_activation_claims(ac, akp).decode("ascii")
    assert jwt

    # verify parts
    parts = jwt.split(".")
    assert len(parts) == 3

    # verify header
    header_json = natsjwt.decode_b64url_no_padding(parts[0])
    header = deserialize_json(header_json, JwtHeader)
    assert header.typ == "JWT"
    assert header.alg == "ed25519-nkey"

    # verify payload
    payload_json = natsjwt.decode_b64url_no_padding(parts[1])
    payload = deserialize_json(payload_json, natsjwt.ActivationClaims)
    assert payload.name == "Activation"
    assert payload.sub == apk
    assert payload.iss == apk
    assert payload.nats.subject == "import.subject"
    assert payload.nats.kind == 1
    assert payload.nats.type == "activation"
    assert payload.nats.version == 2

    # verify signature
    assert parts[2]

    # verify the JWT can be decoded and validated
    decoded_claims = natsjwt.decode_claims(
        jwt.encode("ascii"), natsjwt.ActivationClaims
    )
    assert decoded_claims
    assert decoded_claims.name == ac.name
    assert decoded_claims.sub == ac.sub
    assert decoded_claims.nats.subject == ac.nats.subject
    assert decoded_claims.nats.kind == ac.nats.kind


def test_new_activation_claims() -> None:
    subject = "test.subject"
    claims = natsjwt.new_activation_claims(subject)
    assert claims
    assert claims.sub == subject
    assert claims.nats


def test_new_authorization_request_claims() -> None:
    subject = "auth.request"
    claims = natsjwt.new_authorization_request_claims(subject)
    assert claims
    assert claims.sub == subject
    assert claims.nats


def test_new_authorization_response_claims() -> None:
    subject = "auth.response"
    claims = natsjwt.new_authorization_response_claims(subject)
    assert claims
    assert claims.sub == subject
    assert claims.nats


def test_new_generic_claims() -> None:
    subject = "generic.subject"
    claims = natsjwt.new_generic_claims(subject)
    assert claims
    assert claims.sub == subject


def test_new_operator_claims() -> None:
    subject = "operator.subject"
    claims = natsjwt.new_operator_claims(subject)
    assert claims
    assert claims.sub == subject
    assert claims.iss == subject
    assert claims.nats


def test_new_user_claims() -> None:
    subject = "user.subject"
    claims = natsjwt.new_user_claims(subject)
    assert claims
    assert claims.sub == subject
    assert claims.nats


def test_new_account_claims() -> None:
    subject = "account.subject"
    claims = natsjwt.new_account_claims(subject)
    assert claims
    assert claims.sub == subject
    assert claims.nats


def test_multiple_exports() -> None:
    # Create key pairs
    operator_signing_key = nkeys.create_pair(nkeys.PrefixByte.Operator)
    system_account_key_pair = nkeys.create_pair(nkeys.PrefixByte.Account)

    # Create System Account Claims
    system_account_claims = natsjwt.new_account_claims(
        system_account_key_pair.public_key()
    )
    system_account_claims.name = "SYS"

    # Add exports
    system_account_claims.nats.exports = [
        Export(
            name="account-monitoring-streams",
            subject="y",
            account_token_position=3,
            type=ExportType.Service,
            description="Account specific monitoring stream",
            info_url="https://docs.nats.io/nats-server/configuration/sys_accounts",
        ),
        Export(
            name="account-monitoring-services",
            subject="x",
            account_token_position=4,
            type=ExportType.Service,
            response_type="Stream",
            description="Request account specific monitoring services for: SUBSZ, CONNZ, LEAFZ, JSZ and INFO",
            info_url="https://docs.nats.io/nats-server/configuration/sys_accounts",
        ),
    ]

    # Add imports
    system_account_claims.nats.imports = [
        Import(
            name="account-monitoring",
            subject="y",
            account=system_account_key_pair.public_key(),
            type=ExportType.Service,
            local_subject="account-monitoring",
        ),
        Import(
            name="account-monitoring2",
            subject="x",
            account=system_account_key_pair.public_key(),
            type=ExportType.Service,
            local_subject="account-monitoring2",
        ),
    ]

    # Encode the claims
    jwt = natsjwt.encode_account_claims(
        system_account_claims, operator_signing_key
    ).decode("ascii")

    # Verify the exports are sorted by name
    parts = jwt.split(".")
    payload_json = natsjwt.decode_b64url_no_padding(parts[1])
    payload = deserialize_json(payload_json, natsjwt.AccountClaims)

    # Verify exports (sorted by subject)
    exports = payload.nats.exports
    assert exports
    assert len(exports) == 2
    assert exports[0].subject == "x"
    assert exports[1].subject == "y"

    # Verify imports (sorted by subject)
    imports = payload.nats.imports
    assert imports
    assert len(imports) == 2
    assert imports[0].subject == "x"
    assert imports[1].subject == "y"


def test_decode_user_claim_with_tampered_jwt_raises() -> None:
    jwt = "eyJ0eXAiOiJKV1QiLCJhbGciOiJlZDI1NTE5LW5rZXkifQ.eyJqdGkiOiJPSk9CUkZDQ0NGNEMzU1JWQzRLNEhTVFNYRlBTSVZBSzJPRUxOMlZXNE9GQ0IzQTVMMkNBIiwiaWF0IjoxNzMwMzk3NTU0LCJpc3MiOiJVQklUR0VSQk9JVEZDWkJHNTNUSkk3M1BHTjdBMzdPTVkyWE5YUU82VUZUSlA1TE5VWVFORUpXSSIsIm5hbWUiOiJVWFgiLCJzdWIiOiJVQklUR0VSQk9JVEZDWkJHNTNUSkk3M1BHTjdBMzdPTVkyWE5YUU82VUZUSlA1TE5VWVFORUpXSSIsIm5hdHMiOnsicHViIjp7ImFsbG93IjpbImFsbG93Llx1MDAzRSJdfSwic3ViIjp7ImFsbG93IjpbInN1YnNjcmliZS5cdTAwM0UiXX0sInN1YnMiOi0xLCJkYXRhIjotMSwicGF5bG9hZCI6LTEsInR5cGUiOiJ1c2VyIiwidmVyc2lvbiI6Mn19.SjIBpWWLNCZmgYZwrFHEJSTkm5M9bik0kgQyG-3V9Nn5sTrfO1Llj3hs7z9R7b1rCyGsFm1RkpZAVAnS5ay2BA"
    with pytest.raises(JwtError):
        natsjwt.decode_claims(jwt.encode("ascii"), natsjwt.UserClaims)
