from collections.abc import Mapping, Sequence
from typing import TypeAlias


JsonValue: TypeAlias = (
    str
    | int
    | float
    | bool
    | None
    | Sequence["JsonValue"]
    | Mapping[str, "JsonValue"]
)