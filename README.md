# NATS-py-JWT

WIP implementation of NATS.io utilities needed to handle auth in python: nkeys, xkeys (curve), JWT.
* `src/nkeys` is based on GO implementation (https://github.com/nats-io/nkeys) so it supports curve keys correctly (using PyNaCL)
* `src/natspyjwt` is based on v2 JWT .NET (https://github.com/nats-io/jwt.net) and GO implementation (https://github.com/nats-io/jwt/tree/main/v2)
* `auth_callout_sample.py` is exmaple auth_callout implementation using lib above

NOT FOR PRODUCTION USE YET! (but works)

## Considerations
* memory-leakage of secret data in `nkeys` is not tested properly
* no credential utils to load/save jwts as .creds
* some methods are missing in `jwt` compared to go's jwt impl
* auth_callout example does not properly handle errors, just happy path
* not very pythonic code (was following other implementations closely)
* lack of docs
* not tested under various python interpreters (just Cpython 3.11)

other thatn that it works, mypy complaint and critical functionality if test-covered
