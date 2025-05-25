# NATS-py-JWT

WIP implementation of NATS.io utilities needed to handle auth in python: nkeys, xkeys (curve), JWT.
* `src/nkeys` is based on GO implementation (https://github.com/nats-io/nkeys) so it supports curve keys correctly (using PyNaCL)
* `src/natspyjwt` is based on v2 JWT .NET (https://github.com/nats-io/jwt.net) and GO implementation (https://github.com/nats-io/jwt/tree/main/v2)
* `auth_callout_sample.py` is exmaple auth_callout implementation using lib above

NOT FOR PRODUCTION USE YET!
