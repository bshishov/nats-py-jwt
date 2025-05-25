import pytest
import json

from natspyjwt.serialization import serialize_json, deserialize_json
from natspyjwt.models import ConnectOptions, AccountScopedSigningKey


def test_serialize_deserialize() -> None:
    opts = ConnectOptions(
        name="opts",
        pass_="pass",
    )
    j = serialize_json(opts)
    restored = deserialize_json(j, ConnectOptions)

    assert opts == restored


def test_serialize_pass() -> None:
    opts = ConnectOptions(
        name="opts",
        pass_="pass",
    )
    j = serialize_json(opts)
    assert json.loads(j) == json.loads(
        '{"name": "opts", "pass": "pass", "protocol": 1}'
    )


@pytest.mark.parametrize(
    "tp,fields",
    [
        (ConnectOptions, ["protocol"]),
        (AccountScopedSigningKey, ["kind"]),
    ],
)
def test_default_fields_are_in_place(tp: type, fields: list[str]) -> None:
    j = serialize_json(tp())
    data = json.loads(j)
    keys = list(data.keys())
    assert sorted(keys) == sorted(fields)
