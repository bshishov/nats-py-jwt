import asyncio
import logging
import os
from dataclasses import dataclass
from typing import Optional

import nats
from nats.micro import add_service
from nats.micro.service import ServiceConfig, EndpointConfig, Request

from nkeys import KeyPair, from_seed, from_curve_seed
from natspyjwt import jwt
from natspyjwt.models import Permission


# Config
NATS_URL = os.environ.get("NATS_URL", "nats://localhost:4222")
NATS_USER = os.environ.get("NATS_USER")
NATS_PASSWORD = os.environ.get("NATS_PASSWORD")
ISSUER_NKEY_SEED = os.environ.get("ISSUER_NKEY_SEED")
ENCRYPTION_XKEY_SEED = os.environ.get("ENCRYPTION_XKEY_SEED")


@dataclass
class AuthService:
    _issuer_kp: KeyPair
    _encryption_kp: Optional[KeyPair]

    async def handle(self, request: Request) -> None:
        # TODO: implement proper error handling
        # see https://github.com/synadia-io/rethink_connectivity/blob/main/19-auth-callout/auth-service/auth_service.go#L27

        data = request.data

        # If auth-callout encryption is configured we need to decypher data first
        # using public part from header and private xkey from config
        # assuming that public part of xkey is in server config
        if self._encryption_kp:
            server_key = request.headers["Nats-Server-Xkey"]
            data = self._encryption_kp.open(data, server_key)

        # Decore
        request_claims = jwt.decode_authorization_request_claims(data)

        user_nkey = request_claims.nats.user_nkey
        server_id = request_claims.nats.server_id
        logging.info(f"Received auth request from {user_nkey}")

        # Example auth assuming that each token is valid
        logging.debug(f"user connect_opts: {request_claims.nats.connect_opts}")

        # >> Here we can implement custom auth <<

        # Configure user
        user_claims = jwt.new_user_claims(user_nkey)
        user_claims.aud = "APP"  # make sure that this account is existing server config
        user_claims.name = "test_user"
        user_claims.nats.sub = Permission(allow=["example.*"])
        user_claims.nats.pub = Permission(allow=["example.*"])

        # Encode user claims into JWT and sign with issuer keypair
        user_jwt_token = jwt.encode_user_claims(user_claims, self._issuer_kp)

        # Build response claims for NATS server
        response_claims = jwt.new_authorization_response_claims(user_nkey)
        response_claims.aud = server_id.id
        response_claims.nats.jwt = user_jwt_token.decode("ascii")

        # Encode response claims as JWT
        encoded_response_jwt = jwt.encode_authorization_response_claims(
            response_claims, self._issuer_kp
        )

        # If encryption is enabled we need to properly encrypt responses
        if self._encryption_kp:
            server_key = request.headers["Nats-Server-Xkey"]
            response_data = self._encryption_kp.seal(encoded_response_jwt, server_key)
        else:
            response_data = encoded_response_jwt

        # finally, response
        await request.respond(response_data)
        logging.info(f"Successfully handled auth request for {user_nkey}")


async def main() -> None:
    logging.basicConfig(level=logging.DEBUG)

    assert ISSUER_NKEY_SEED, "ISSUER_NKEY_SEED is required to issue client JWTs"

    # Keypairs setup
    auth_service = AuthService(
        _issuer_kp=from_seed(ISSUER_NKEY_SEED.encode("ascii")),
        _encryption_kp=(
            from_curve_seed(ENCRYPTION_XKEY_SEED.encode("ascii"))
            if ENCRYPTION_XKEY_SEED
            else None
        ),
    )

    # Connection
    async def reconnected_cb() -> None:
        logging.info(f"Got reconnected to {nc.connected_url.netloc}")

    async def error_cb(e):
        logging.error(f"Nats error: {e}")

    nc = await nats.connect(
        servers=NATS_URL.split(","),
        user=NATS_USER,
        password=NATS_PASSWORD,
        reconnected_cb=reconnected_cb,
        error_cb=error_cb,
    )
    logging.info(f"NATS Connected to {nc.connected_url.netloc}")

    # Configure service
    service = await add_service(nc, ServiceConfig("auth-service", version="0.0.1"))
    await service.add_endpoint(
        EndpointConfig(
            name="auth", handler=auth_service.handle, subject="$SYS.REQ.USER.AUTH"
        )
    )

    while nc.is_connected:
        try:
            await asyncio.sleep(60)
        except (asyncio.CancelledError, KeyboardInterrupt):
            break

    await nc.close()


if __name__ == "__main__":
    asyncio.run(main())
