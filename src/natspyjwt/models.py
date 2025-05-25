from __future__ import annotations

from enum import Enum
from typing import Any

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
    mem_storage: int | None = None
    disk_storage: int | None = None
    streams: int | None = None
    consumer: int | None = None
    max_ack_pending: int | None = None
    mem_max_stream_bytes: int | None = None
    disk_max_stream_bytes: int | None = None
    max_bytes_required: bool | None = None


@dataclass
class JwtHeader:
    typ: str | None = None
    alg: str | None = None

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
    tags: TagList | None = None
    type: str | None = None
    version: int | None = None


@dataclass
class JwtClaimsData:
    aud: str | None = None  # audience
    jti: str | None = None  # jwt id
    iat: int | None = None  # issued at
    iss: str | None = None  # issuer
    name: str | None = None
    sub: str | None = None  # subject
    exp: int | None = None  # expiration time
    nbf: int | None = None  # not before

    def expected_prefixes(self) -> list[nkeys.PrefixByte]:
        raise JwtInvalidClaimError


@dataclass
class Account(GenericFields):
    imports: list[Import] | None = None
    exports: list[Export] | None = None
    limits: OperatorLimits | None = None
    signing_keys: list[AccountSigningKey] | None = None
    revocations: dict[str, int] | None = None
    default_permissions: Permissions | None = None
    mappings: dict[str, list[WeightedMapping]] | None = None
    external: ExternalAuthorization | None = None
    trace: MsgTrace | None = None
    description: str | None = None
    info_url: str | None = None


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
    key: str | None = None
    role: str | None = None
    template: User | None = None


@dataclass
class Activation(GenericFields):
    subject: str | None = None  # ImportSubject
    kind: int | None = None  # ImportType
    issuer_account: str | None = None


@dataclass
class ActivationClaims(JwtClaimsData):
    nats: Activation = field(factory=Activation)

    def expected_prefixes(self) -> list[nkeys.PrefixByte]:
        return [nkeys.PrefixByte.Account, nkeys.PrefixByte.Operator]


@dataclass
class AuthorizationRequest(GenericFields):
    server_id: ServerId | None = None
    user_nkey: str | None = None
    client_info: ClientInformation | None = None
    connect_opts: ConnectOptions | None = None
    client_tls: ClientTls | None = None
    request_nonce: str | None = None


@dataclass
class AuthorizationRequestClaims(JwtClaimsData):
    nats: AuthorizationRequest = field(factory=AuthorizationRequest)

    def expected_prefixes(self) -> list[nkeys.PrefixByte]:
        return [nkeys.PrefixByte.Server]


@dataclass
class AuthorizationResponse(GenericFields):
    jwt: str | None = None
    error: str | None = None
    issuer_account: str | None = None


@dataclass
class AuthorizationResponseClaims(JwtClaimsData):
    nats: AuthorizationResponse = field(factory=AuthorizationResponse)

    def expected_prefixes(self) -> list[nkeys.PrefixByte]:
        return [nkeys.PrefixByte.Account]


@dataclass
class ClientInformation:
    host: str | None = None
    id: int | None = None
    user: str | None = None
    name: str | None = None
    tags: TagList | None = None
    name_tag: str | None = None
    kind: str | None = None
    type: str | None = None
    mqtt_id: str | None = None
    nonce: str | None = None


@dataclass
class ClientTls:
    version: str | None = None
    cipher: str | None = None
    certs: list[str] | None = None
    verified_chains: list[list[str]] | None = None


@dataclass
class ConnectOptions:
    jwt: str | None = None
    nkey: str | None = None
    sig: str | None = None
    auth_token: str | None = None
    user: str | None = None
    pass_: str | None = None
    name: str | None = None
    lang: str | None = None
    version: str | None = None
    protocol: int = 1


@dataclass
class Export:
    name: str | None = None
    subject: str | None = None
    type: ExportType | None = None
    token_req: bool | None = None
    revocations: dict[str, int] | None = None
    response_type: str | None = None
    response_threshold: int | None = None  # nanoseconds
    latency: ServiceLatency | None = None
    account_token_position: int | None = None
    advertise: bool | None = None
    allow_trace: bool | None = None
    description: str | None = None
    info_url: str | None = None


class ExportType(Enum):
    Unknown = "unknown"
    Stream = "stream"
    Service = "service"


@dataclass
class ExternalAuthorization:
    auth_users: list[str] | None = None
    allowed_accounts: list[str] | None = None
    xkey: str | None = None


@dataclass
class GenericClaims(JwtClaimsData):
    nats: dict[str, Any] = field(factory=dict)

    def expected_prefixes(self) -> list[nkeys.PrefixByte]:
        return []


@dataclass
class GenericFieldsClaims(JwtClaimsData):
    nats: GenericFields | None = None


@dataclass
class Import:
    name: str | None = None
    subject: str | None = None
    account: str | None = None
    token: str | None = None
    to: str | None = None
    local_subject: str | None = None
    type: ExportType | None = None
    share: bool | None = None
    allow_trace: bool | None = None


@dataclass
class MsgTrace:
    dest: str | None = None
    sampling: int | None = None


@dataclass
class Operator(GenericFields):
    signing_keys: list[str] | None = None
    account_server_url: str | None = None
    operator_service_urls: list[str] | None = None
    system_account: str | None = None
    assert_server_version: str | None = None
    strict_signing_key_usage: bool | None = None


@dataclass
class OperatorClaims(JwtClaimsData):
    nats: Operator = field(factory=Operator)

    def expected_prefixes(self) -> list[nkeys.PrefixByte]:
        return [nkeys.PrefixByte.Operator]


@dataclass
class OperatorLimits:
    subs: int | None = None
    data: int | None = None
    payload: int | None = None
    imports: int | None = None
    exports: int | None = None
    wildcards: bool | None = None
    disallow_bearer: bool | None = None
    conn: int | None = None
    leaf: int | None = None
    mem_storage: int | None = None
    disk_storage: int | None = None
    streams: int | None = None
    consumer: int | None = None
    max_ack_pending: int | None = None
    mem_max_stream_bytes: int | None = None
    disk_max_stream_bytes: int | None = None
    max_bytes_required: bool | None = None
    tiered_limits: dict[str, JetStreamLimits] | None = None


@dataclass
class Permission:
    allow: list[str] | None = None
    deny: list[str] | None = None


@dataclass
class Permissions:
    pub: Permission | None = None
    sub: Permission | None = None
    resp: Permission | None = None


@dataclass
class ResponsePermission:
    max: int | None = None
    ttl: int | None = None


@dataclass
class ServerId:
    name: str | None = None
    host: str | None = None
    id: str | None = None
    version: str | None = None
    cluster: str | None = None
    tags: TagList | None = None
    xkey: str | None = None


@dataclass
class ServiceLatency:
    sampling: int | None = None
    results: str | None = None


@dataclass
class User(GenericFields):
    pub: Permission = field(factory=Permission)
    sub: Permission = field(factory=Permission)
    resp: ResponsePermission | None = None
    src: list[str] | None = None
    times: list[TimeRange] | None = None
    locale: str | None = None
    subs: int | None = None
    data: int | None = None
    payload: int | None = None
    bearer_token: bool | None = None
    allowed_connection_types: list[str] | None = None
    issuer_account: str | None = None


@dataclass
class UserClaims(JwtClaimsData):
    nats: User = field(factory=User)

    def expected_prefixes(self) -> list[nkeys.PrefixByte]:
        return [nkeys.PrefixByte.Account]


@dataclass
class WeightedMapping:
    subject: str | None = None
    weight: int | None = None  # byte
    cluster: str | None = None


@dataclass
class TimeRange:
    start: str | None = None
    end: str | None = None
