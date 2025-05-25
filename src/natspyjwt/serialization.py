from attr import fields, has
from typing import TypeVar, Type, Any

from cattrs.preconf.json import make_converter, JsonConverter
from cattrs import override
from cattrs.gen import make_dict_structure_fn


__all__ = [
    "serialize_json",
    "deserialize_json",
]

_T = TypeVar("_T")


def _create_converter() -> JsonConverter:
    converter = make_converter(omit_if_default=True)

    def un_structure_hook_factory(cls: Type[_T]) -> Any:
        cls_fields = fields(cls)  # type: ignore
        overrides = {
            f.name: override(rename=f.name.rstrip("_"))
            for f in cls_fields
            if f.name.endswith("_")
        }

        def un_structure_hook(obj: _T) -> dict:
            result = {}
            for f in cls_fields:
                val = getattr(obj, f.name)
                if val is not None:
                    key = overrides.get(f.name, override()).rename or f.name
                    result[key] = converter.unstructure(val)
            return result

        return un_structure_hook

    def structure_hook_factory(cls: Type[_T]) -> Any:
        cls_fields = fields(cls)  # type: ignore
        overrides = {
            f.name: override(rename=f.name.rstrip("_"))
            for f in cls_fields
            if f.name.endswith("_")
        }
        return make_dict_structure_fn(cls, converter, **overrides)  # type: ignore

    # Hook factories for attrs dataclasses (`has` is an attrs predicate)
    converter.register_unstructure_hook_factory(has, un_structure_hook_factory)
    converter.register_structure_hook_factory(has, structure_hook_factory)

    return converter


_CONVERTER = _create_converter()


def serialize_json(obj: object) -> str:
    return _CONVERTER.dumps(obj)


def deserialize_json(data: str | bytes, tp: Type[_T]) -> _T:
    return _CONVERTER.loads(data, tp)
