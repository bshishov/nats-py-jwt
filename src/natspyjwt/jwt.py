from typing import TypeVar, Union, Optional
import base64
import json
import datetime
from datetime import timezone
from hashlib import sha256

import nkeys
from nkeys import KeyPair, from_public_key

from .errors import JwtInvalidClaimError, JwtDecodeError
from .models import (
    OperatorClaims,
    JwtHeader,
    JwtClaimsData,
    GenericFields,
    UserClaims,
    AccountClaims,
    ActivationClaims,
    AuthorizationRequestClaims,
    AuthorizationResponseClaims,
    GenericClaims,
)
from .serialization import serialize_json, deserialize_json

__all__ = [
    "new_activation_claims",
    "new_authorization_request_claims",
    "new_authorization_response_claims",
    "new_generic_claims",
    "new_operator_claims",
    "new_user_claims",
    "new_account_claims",
    "encode_activation_claims",
    "encode_authorization_request_claims",
    "encode_authorization_response_claims",
    "encode_generic_claims",
    "encode_operator_claims",
    "encode_user_claims",
    "encode_account_claims",
    "decode_operator_claims",
    "decode_user_claims",
    "decode_authorization_request_claims",
    "decode_account_claims",
    "decode_activation_claims",
    "decode_claims",
    "encode_b64url_no_padding",
    "decode_b64url_no_padding",
    "serialize",
]

TGeneric = TypeVar("TGeneric", bound=GenericFields)
TClaimData = TypeVar("TClaimData", bound=JwtClaimsData)


LIBRARY_VERSION = 2
NO_LIMIT = -1
ANY_ACCOUNT = "*"

OPERATOR_CLAIM = "operator"
ACCOUNT_CLAIM = "account"
USER_CLAIM = "user"
ACTIVATION_CLAIM = "activation"
AUTHORIZATION_REQUEST_CLAIM = "authorization_request"
AUTHORIZATION_RESPONSE_CLAIM = "authorization_response"
GENERIC_CLAIM = "generic"

JWT_HEADER = JwtHeader(typ="JWT", alg="ed25519-nkey")
JWT_ENCODING = "utf-8"

CLAIM_TYPES: dict[str, type[JwtClaimsData]] = {
    USER_CLAIM: UserClaims,
    OPERATOR_CLAIM: OperatorClaims,
    ACCOUNT_CLAIM: AccountClaims,
    ACTIVATION_CLAIM: ActivationClaims,
    AUTHORIZATION_REQUEST_CLAIM: AuthorizationRequestClaims,
}


def new_activation_claims(subject: str) -> ActivationClaims:
    return ActivationClaims(sub=subject)


def new_authorization_request_claims(subject: str) -> AuthorizationRequestClaims:
    return AuthorizationRequestClaims(sub=subject)


def new_authorization_response_claims(subject: str) -> AuthorizationResponseClaims:
    return AuthorizationResponseClaims(sub=subject)


def new_generic_claims(subject: str) -> GenericClaims:
    return GenericClaims(sub=subject)


def new_operator_claims(subject: str) -> OperatorClaims:
    return OperatorClaims(sub=subject, iss=subject)


def new_user_claims(subject: str) -> UserClaims:
    return UserClaims(sub=subject)


def new_account_claims(subject: str) -> AccountClaims:
    return AccountClaims(sub=subject)


def set_version(claims: TGeneric, tp: str) -> None:
    claims.type = tp
    claims.version = LIBRARY_VERSION


def encode_activation_claims(
    claims: ActivationClaims, kp: KeyPair, issued_at: Optional[int] = None
) -> bytes:
    set_version(claims.nats, ACTIVATION_CLAIM)
    return do_encode(JWT_HEADER, kp, claims, issued_at)


def encode_authorization_request_claims(
    claims: AuthorizationRequestClaims, kp: KeyPair, issued_at: Optional[int]
) -> bytes:
    set_version(claims.nats, AUTHORIZATION_REQUEST_CLAIM)
    return do_encode(JWT_HEADER, kp, claims, issued_at)


def encode_authorization_response_claims(
    claims: AuthorizationResponseClaims, kp: KeyPair, issued_at: Optional[int] = None
) -> bytes:
    set_version(claims.nats, AUTHORIZATION_RESPONSE_CLAIM)
    return do_encode(JWT_HEADER, kp, claims, issued_at)


def encode_generic_claims(
    claims: GenericClaims, kp: KeyPair, issued_at: Optional[int] = None
) -> bytes:
    return do_encode(JWT_HEADER, kp, claims, issued_at)


def encode_operator_claims(
    claims: OperatorClaims, kp: KeyPair, issued_at: Optional[int] = None
) -> bytes:
    set_version(claims.nats, OPERATOR_CLAIM)
    return do_encode(JWT_HEADER, kp, claims, issued_at)


def encode_user_claims(
    claims: UserClaims, kp: KeyPair, issued_at: Optional[int] = None
) -> bytes:
    set_version(claims.nats, USER_CLAIM)
    return do_encode(JWT_HEADER, kp, claims, issued_at)


def encode_account_claims(
    claims: AccountClaims, kp: KeyPair, issued_at: Optional[int] = None
) -> bytes:
    set_version(claims.nats, ACCOUNT_CLAIM)

    if claims.nats.exports:
        claims.nats.exports.sort(key=lambda x: x.subject or "" if x else "")

    if claims.nats.imports:
        claims.nats.imports.sort(key=lambda x: x.subject or "" if x else "")

    return do_encode(JWT_HEADER, kp, claims, issued_at)


def decode_operator_claims(jwt: bytes) -> OperatorClaims:
    claims = decode_claims(jwt, OperatorClaims)
    if claims.nats.type != OPERATOR_CLAIM:
        raise JwtDecodeError(
            f"Expected {OPERATOR_CLAIM} claim, but got {claims.nats.type}"
        )
    return claims


def decode_account_claims(jwt: bytes) -> AccountClaims:
    claims = decode_claims(jwt, AccountClaims)
    if claims.nats.type != ACCOUNT_CLAIM:
        raise JwtDecodeError(
            f"Expected {ACCOUNT_CLAIM} claim, but got {claims.nats.type}"
        )
    return claims


def decode_user_claims(jwt: bytes) -> UserClaims:
    claims = decode_claims(jwt, UserClaims)
    if claims.nats.type != USER_CLAIM:
        raise JwtDecodeError(f"Expected {USER_CLAIM} claim, but got {claims.nats.type}")
    return claims


def decode_activation_claims(jwt: bytes) -> ActivationClaims:
    claims = decode_claims(jwt, ActivationClaims)
    if claims.nats.type != ACTIVATION_CLAIM:
        raise JwtDecodeError(
            f"Expected {ACTIVATION_CLAIM} claim, but got {claims.nats.type}"
        )
    return claims


def decode_authorization_request_claims(jwt: bytes) -> AuthorizationRequestClaims:
    claims = decode_claims(jwt, AuthorizationRequestClaims)
    if claims.nats.type != AUTHORIZATION_REQUEST_CLAIM:
        raise JwtDecodeError(
            f"Expected {AUTHORIZATION_REQUEST_CLAIM} claim, but got {claims.nats.type}"
        )
    return claims


def decode_claims(jwt: bytes, claim_type: type[TClaimData]) -> TClaimData:
    parts = jwt.split(b".")
    if len(parts) != 3:
        raise JwtDecodeError("Invalid JWT format")

    header_json = decode_b64url_no_padding(parts[0]).decode("utf-8")
    try:
        header = deserialize_json(header_json, JwtHeader)
    except TypeError:
        raise JwtDecodeError("Can't parse JWT header")
    header.validate()

    payload_json = decode_b64url_no_padding(parts[1])
    kind, version = _kind_and_version(payload_json)

    if version > LIBRARY_VERSION:
        raise JwtDecodeError("JWT was generated by a newer version")

    expected_claim_type = CLAIM_TYPES.get(kind)
    if not expected_claim_type:
        raise JwtDecodeError(f"Unsupported claim type {kind}")

    if expected_claim_type != claim_type:
        raise JwtDecodeError(
            f"Claim type mismatch: requested {claim_type.__name__} but found {expected_claim_type.__name__} (for {kind}) in JWT"
        )

    claims = deserialize_json(payload_json.decode("utf-8"), claim_type)
    if not claims.iss:
        raise JwtDecodeError("Invalid JWT, missing issuer")

    sig = decode_b64url_no_padding(parts[2])
    if version <= 1:
        _verify_signature(parts[1], sig, claims.iss)
    else:
        _verify_signature(b"%s.%s" % (parts[0], parts[1]), sig, claims.iss)

    return claims


def _verify_signature(payload: bytes, signature: bytes, issuer: str) -> None:
    public_kp = from_public_key(issuer)
    if not public_kp.verify(payload, signature):
        raise JwtDecodeError("JWT signature verification failed")


def do_encode(
    jwt_header: JwtHeader, kp: KeyPair, claim: TClaimData, issued_at: Optional[int]
) -> bytes:
    jwt_header.validate()
    h = serialize(jwt_header)
    c = claim

    if not c.sub:
        raise JwtInvalidClaimError("Subject is not set")

    issuer = kp.public_key()
    issuer_bytes = issuer.encode("ascii")
    ok = False
    for prefix in claim.expected_prefixes():
        if prefix == nkeys.PrefixByte.Account:
            if nkeys.is_valid_public_account_key(issuer_bytes):
                ok = True
                break
        if prefix == nkeys.PrefixByte.Operator:
            if nkeys.is_valid_public_operator_key(issuer_bytes):
                ok = True
                break
        if prefix == nkeys.PrefixByte.Server:
            if nkeys.is_valid_public_server_key(issuer_bytes):
                ok = True
                break
        if prefix == nkeys.PrefixByte.Cluster:
            if nkeys.is_valid_public_cluster_key(issuer_bytes):
                ok = True
                break
        if prefix == nkeys.PrefixByte.User:
            if nkeys.is_valid_public_user_key(issuer_bytes):
                ok = True
                break

    if not ok:
        raise JwtInvalidClaimError("Invalid signing key")

    c.iss = issuer
    c.iat = issued_at or utc_now_timestamp()
    c.jti = ""
    c.jti = hash_claims(c).decode("ascii")

    payload = serialize(c)
    to_sign = b"%s.%s" % (h, payload)

    sig = kp.sign(to_sign)
    encoded_sig = encode_b64url_no_padding(sig)

    return b"%s.%s" % (to_sign, encoded_sig)


def _kind_and_version(jwt_payload: Union[str, bytes]) -> tuple[str, int]:
    jwt_payload_data = json.loads(jwt_payload)
    typ = jwt_payload_data.get("type")
    if typ:
        return typ, 1

    nats = jwt_payload_data.get("nats")
    if not nats or not isinstance(nats, dict):
        raise JwtDecodeError("Failed to get nats element")

    raw_version = nats.get("version")
    if not raw_version:
        raise JwtDecodeError("Failed to get nats.version element")

    try:
        nats_version = int(raw_version)
    except (ValueError, TypeError):
        raise JwtDecodeError("Failed to get nats.version as integer")

    nats_type = nats.get("type")
    if not nats_type or not isinstance(nats_type, str):
        raise JwtDecodeError("Failed to get nats.type element")

    return nats_type, nats_version


def serialize(o: object) -> bytes:
    j = serialize_json(o)
    return encode_b64url_no_padding(j.encode(JWT_ENCODING))


def decode_b64url_no_padding(s: Union[str, bytes]) -> bytes:
    pad = -len(s) % 4
    if pad == 0:
        return base64.urlsafe_b64decode(s)

    if isinstance(s, str):
        s = bytearray(s, "ascii")
    return base64.urlsafe_b64decode(s + b"=" * pad)


def encode_b64url_no_padding(data: bytes) -> bytes:
    return base64.urlsafe_b64encode(data).rstrip(b"=")


def hash_claims(c: JwtClaimsData) -> bytes:
    j = serialize_json(c)
    h = sha256(j.encode(JWT_ENCODING)).digest()
    return base64.b32encode(h).rstrip(b"=")


def utc_now_timestamp() -> int:
    return int(datetime.datetime.now(tz=timezone.utc).timestamp())
