import asyncio
import re
import os

from pydantic import ValidationError, validate_call
from typing import Any, Literal
from copy import deepcopy
from uuid import UUID


def merge_deep(dict1: dict, dict2: dict):
    result = deepcopy(dict1)

    def _recursive_merge(_dict1, _dict2):
        for key in _dict2:
            if (
                key in _dict1
                and isinstance(_dict1[key], dict)
                and isinstance(_dict2[key], dict)
            ):
                _recursive_merge(_dict1[key], _dict2[key])
            else:
                _dict1[key] = _dict2[key]

    _recursive_merge(result, dict2)
    return result


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
def to_unique_sorted_str_list(l: list[str | UUID]) -> list:
    _l = [str(x) for x in set(l) if x]
    return sorted(_l)


@validate_call
def to_unique_list(l: list[Any]) -> list:
    _l = [x for x in set(l) if x]
    return sorted(_l)


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


# https://stackoverflow.com/a/73195814
@validate_call
def read_n_to_last_line(filename, n: int = 1):
    assert is_path_within_cwd(filename)
    if not os.path.isfile(filename):
        return
    num_newlines = 0
    with open(filename, "rb") as f:
        try:
            f.seek(-2, os.SEEK_END)
            while num_newlines < n:
                f.seek(-2, os.SEEK_CUR)
                if f.read(1) == b"\n":
                    num_newlines += 1
        except OSError:
            f.seek(0)
        last_line = f.readline().decode()
    return last_line
