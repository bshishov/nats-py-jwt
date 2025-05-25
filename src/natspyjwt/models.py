from __future__ import annotations

from enum import Enum
from typing import Any, Optional

import nkeys
from attr import dataclass, field

from natspyjwt.errors import JwtInvalidHeaderError, JwtInvalidClaimError

__all__ = [
    "TagList",
    "JetStreamLimits",
    "JwtHeader",
    "GenericFields",
    "JwtClaimsData",
    "AccountClaims",
    "AccountSigningKey",
    "AccountScopedSigningKey",
    "Activation",
    "ActivationClaims",
    "AuthorizationRequest",
    "AuthorizationRequestClaims",
    "AuthorizationResponse",
    "AuthorizationResponseClaims",
    "ClientInformation",
    "ClientTls",
    "ConnectOptions",
    "Export",
    "ExportType",
    "ExternalAuthorization",
    "GenericClaims",
    "GenericFieldsClaims",
    "Import",
    "MsgTrace",
    "Operator",
    "OperatorClaims",
    "OperatorLimits",
    "Permission",
    "Permissions",
    "ResponsePermission",
    "ServerId",
    "ServiceLatency",
    "User",
    "UserClaims",
    "WeightedMapping",
    "TimeRange",
]


TagList = list[str]


@dataclass
class JetStreamLimits:
    mem_storage: Optional[int] = None
    disk_storage: Optional[int] = None
    streams: Optional[int] = None
    consumer: Optional[int] = None
    max_ack_pending: Optional[int] = None
    mem_max_stream_bytes: Optional[int] = None
    disk_max_stream_bytes: Optional[int] = None
    max_bytes_required: Optional[bool] = None


@dataclass
class JwtHeader:
    typ: Optional[str] = None
    alg: Optional[str] = None

    def validate(self) -> None:
        if self.typ != "JWT":
            raise JwtInvalidHeaderError(
                f"Invalid JWT header: not supported type {self.typ}"
            )
        if self.alg != "ed25519" and self.alg != "ed25519-nkey":
            raise JwtInvalidHeaderError(
                f"Invalid JWT header: unexpected {self.alg} algorithm"
            )


@dataclass
class GenericFields:
    tags: Optional[TagList] = None
    type: Optional[str] = None
    version: Optional[int] = None


@dataclass
class JwtClaimsData:
    aud: Optional[str] = None  # audience
    jti: Optional[str] = None  # jwt id
    iat: Optional[int] = None  # issued at
    iss: Optional[str] = None  # issuer
    name: Optional[str] = None
    sub: Optional[str] = None  # subject
    exp: Optional[int] = None  # expiration time
    nbf: Optional[int] = None  # not before

    def expected_prefixes(self) -> list[nkeys.PrefixByte]:
        raise JwtInvalidClaimError


@dataclass
class Account(GenericFields):
    imports: Optional[list[Import]] = None
    exports: Optional[list[Export]] = None
    limits: Optional[OperatorLimits] = None
    signing_keys: Optional[list[AccountSigningKey]] = None
    revocations: Optional[dict[str, int]] = None
    default_permissions: Optional[Permissions] = None
    mappings: dict[str, Optional[list[WeightedMapping]]] = None
    external: Optional[ExternalAuthorization] = None
    trace: Optional[MsgTrace] = None
    description: Optional[str] = None
    info_url: Optional[str] = None


@dataclass
class AccountClaims(JwtClaimsData):
    nats: Account = field(factory=Account)

    def expected_prefixes(self) -> list[nkeys.PrefixByte]:
        return [nkeys.PrefixByte.Account, nkeys.PrefixByte.Operator]


class AccountSigningKey:
    def __init__(self, signing_key: str) -> None:
        self._signing_key = signing_key

    def __str__(self) -> str:
        return self._signing_key

    def __repr__(self) -> str:
        return self._signing_key


@dataclass
class AccountScopedSigningKey(AccountSigningKey):
    kind: str = "user_scope"
    key: Optional[str] = None
    role: Optional[str] = None
    template: Optional[User] = None


@dataclass
class Activation(GenericFields):
    subject: Optional[str] = None  # ImportSubject
    kind: Optional[int] = None  # ImportType
    issuer_account: Optional[str] = None


@dataclass
class ActivationClaims(JwtClaimsData):
    nats: Activation = field(factory=Activation)

    def expected_prefixes(self) -> list[nkeys.PrefixByte]:
        return [nkeys.PrefixByte.Account, nkeys.PrefixByte.Operator]


@dataclass
class AuthorizationRequest(GenericFields):
    server_id: Optional[ServerId] = None
    user_nkey: Optional[str] = None
    client_info: Optional[ClientInformation] = None
    connect_opts: Optional[ConnectOptions] = None
    client_tls: Optional[ClientTls] = None
    request_nonce: Optional[str] = None


@dataclass
class AuthorizationRequestClaims(JwtClaimsData):
    nats: AuthorizationRequest = field(factory=AuthorizationRequest)

    def expected_prefixes(self) -> list[nkeys.PrefixByte]:
        return [nkeys.PrefixByte.Server]


@dataclass
class AuthorizationResponse(GenericFields):
    jwt: Optional[str] = None
    error: Optional[str] = None
    issuer_account: Optional[str] = None


@dataclass
class AuthorizationResponseClaims(JwtClaimsData):
    nats: AuthorizationResponse = field(factory=AuthorizationResponse)

    def expected_prefixes(self) -> list[nkeys.PrefixByte]:
        return [nkeys.PrefixByte.Account]


@dataclass
class ClientInformation:
    host: Optional[str] = None
    id: Optional[int] = None
    user: Optional[str] = None
    name: Optional[str] = None
    tags: Optional[TagList] = None
    name_tag: Optional[str] = None
    kind: Optional[str] = None
    type: Optional[str] = None
    mqtt_id: Optional[str] = None
    nonce: Optional[str] = None


@dataclass
class ClientTls:
    version: Optional[str] = None
    cipher: Optional[str] = None
    certs: Optional[list[str]] = None
    verified_chains: Optional[list[list[str]]] = None


@dataclass
class ConnectOptions:
    jwt: Optional[str] = None
    nkey: Optional[str] = None
    sig: Optional[str] = None
    auth_token: Optional[str] = None
    user: Optional[str] = None
    pass_: Optional[str] = None
    name: Optional[str] = None
    lang: Optional[str] = None
    version: Optional[str] = None
    protocol: int = 1


@dataclass
class Export:
    name: Optional[str] = None
    subject: Optional[str] = None
    type: Optional[ExportType] = None
    token_req: Optional[bool] = None
    revocations: dict[str, Optional[int]] = None
    response_type: Optional[str] = None
    response_threshold: Optional[int] = None  # nanoseconds
    latency: Optional[ServiceLatency] = None
    account_token_position: Optional[int] = None
    advertise: Optional[bool] = None
    allow_trace: Optional[bool] = None
    description: Optional[str] = None
    info_url: Optional[str] = None


class ExportType(Enum):
    Unknown = "unknown"
    Stream = "stream"
    Service = "service"


@dataclass
class ExternalAuthorization:
    auth_users: Optional[list[str]] = None
    allowed_accounts: Optional[list[str]] = None
    xkey: Optional[str] = None


@dataclass
class GenericClaims(JwtClaimsData):
    nats: dict[str, Any] = field(factory=dict)

    def expected_prefixes(self) -> list[nkeys.PrefixByte]:
        return []


@dataclass
class GenericFieldsClaims(JwtClaimsData):
    nats: Optional[GenericFields] = None


@dataclass
class Import:
    name: Optional[str] = None
    subject: Optional[str] = None
    account: Optional[str] = None
    token: Optional[str] = None
    to: Optional[str] = None
    local_subject: Optional[str] = None
    type: Optional[ExportType] = None
    share: Optional[bool] = None
    allow_trace: Optional[bool] = None


@dataclass
class MsgTrace:
    dest: Optional[str] = None
    sampling: Optional[int] = None


@dataclass
class Operator(GenericFields):
    signing_keys: Optional[list[str]] = None
    account_server_url: Optional[str] = None
    operator_service_urls: Optional[list[str]] = None
    system_account: Optional[str] = None
    assert_server_version: Optional[str] = None
    strict_signing_key_usage: Optional[bool] = None


@dataclass
class OperatorClaims(JwtClaimsData):
    nats: Operator = field(factory=Operator)

    def expected_prefixes(self) -> list[nkeys.PrefixByte]:
        return [nkeys.PrefixByte.Operator]


@dataclass
class OperatorLimits:
    subs: Optional[int] = None
    data: Optional[int] = None
    payload: Optional[int] = None
    imports: Optional[int] = None
    exports: Optional[int] = None
    wildcards: Optional[bool] = None
    disallow_bearer: Optional[bool] = None
    conn: Optional[int] = None
    leaf: Optional[int] = None
    mem_storage: Optional[int] = None
    disk_storage: Optional[int] = None
    streams: Optional[int] = None
    consumer: Optional[int] = None
    max_ack_pending: Optional[int] = None
    mem_max_stream_bytes: Optional[int] = None
    disk_max_stream_bytes: Optional[int] = None
    max_bytes_required: Optional[bool] = None
    tiered_limits: dict[str, Optional[JetStreamLimits]] = None


@dataclass
class Permission:
    allow: Optional[list[str]] = None
    deny: Optional[list[str]] = None


@dataclass
class Permissions:
    pub: Optional[Permission] = None
    sub: Optional[Permission] = None
    resp: Optional[Permission] = None


@dataclass
class ResponsePermission:
    max: Optional[int] = None
    ttl: Optional[int] = None


@dataclass
class ServerId:
    name: Optional[str] = None
    host: Optional[str] = None
    id: Optional[str] = None
    version: Optional[str] = None
    cluster: Optional[str] = None
    tags: Optional[TagList] = None
    xkey: Optional[str] = None


@dataclass
class ServiceLatency:
    sampling: Optional[int] = None
    results: Optional[str] = None


@dataclass
class User(GenericFields):
    pub: Permission = field(factory=Permission)
    sub: Permission = field(factory=Permission)
    resp: Optional[ResponsePermission] = None
    src: Optional[list[str]] = None
    times: Optional[list[TimeRange]] = None
    locale: Optional[str] = None
    subs: Optional[int] = None
    data: Optional[int] = None
    payload: Optional[int] = None
    bearer_token: Optional[bool] = None
    allowed_connection_types: Optional[list[str]] = None
    issuer_account: Optional[str] = None


@dataclass
class UserClaims(JwtClaimsData):
    nats: User = field(factory=User)

    def expected_prefixes(self) -> list[nkeys.PrefixByte]:
        return [nkeys.PrefixByte.Account]


@dataclass
class WeightedMapping:
    subject: Optional[str] = None
    weight: Optional[int] = None  # byte
    cluster: Optional[str] = None


@dataclass
class TimeRange:
    start: Optional[str] = None
    end: Optional[str] = None
