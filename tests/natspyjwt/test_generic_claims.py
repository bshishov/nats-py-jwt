from natspyjwt.models import GenericClaims
from natspyjwt.serialization import serialize_json, deserialize_json


def test_generic_claims() -> None:
    claims = GenericClaims()
    claims.nats = {
        "user": {
            "name": "John Doe",
            "email": "john@example.com",
            "roles": ["admin", "user"],
        },
    }

    data = serialize_json(claims)
    claims2 = deserialize_json(data, GenericClaims)
    data2 = serialize_json(claims2)
    assert data == data2
