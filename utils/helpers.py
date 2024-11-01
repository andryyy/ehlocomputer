import asyncio, re, os

from pydantic import ValidationError, validate_call
from typing import Any, Literal


@validate_call
def batch(l: list, n: int):
    _l = len(l)
    for ndx in range(0, _l, n):
        yield l[ndx : min(ndx + n, _l)]


@validate_call
def get_validated_fqdn(hostname: str) -> str:
    regex = re.compile(
        r"^((?![-])[-A-Z\d]{1,63}(?<!-)[.])*(?!-)[-A-Z\d]{1,63}(?<!-)?$", re.IGNORECASE
    )
    if len(hostname) > 253:
        raise ValueError(f"{hostname or 'None'} is too long")
    if regex.match(hostname):
        return hostname
    else:
        raise ValueError(f"{hostname or 'None'} is not a valid FQDN")


@validate_call
def ensure_list(a: Any | list[Any] | None) -> list:
    if a:
        if not isinstance(a, list):
            return [a]
        return a
    return []


@validate_call
def to_unique_sorted_str_list(l: list[str]) -> list:
    _l = [x for x in set(l) if x]
    return sorted(_l, key=lambda x: str(x))


@validate_call
def to_unique_list(l: list[Any]) -> list:
    _l = [x for x in set(l) if x]
    return sorted(_l, key=lambda x: x)


@validate_call
def flatten(l: list[list]):
    return [i for sub_list in l for i in sub_list]


@validate_call
def is_path_within_cwd(path):
    requested_path = os.path.abspath(path)
    return requested_path.startswith(os.path.abspath("."))


async def expire_key(in_dict: dict, dict_key: int | str, wait_time: float | int):
    await asyncio.sleep(wait_time)
    in_dict.pop(dict_key, None)
