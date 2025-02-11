import asyncio
import re
import os

from pydantic import ValidationError, validate_call, BaseModel
from typing import Any, Literal
from copy import deepcopy
from uuid import UUID


# Returns new model (based on original model) using
# deep merged data of both input models data
def merge_models(
    original: BaseModel, override: BaseModel, post_data_keys: list | None = None
) -> BaseModel:
    # Convert both models to dictionaries
    original_data = original.model_dump(mode="json")
    override_data = override.model_dump(mode="json")

    # Merge with override taking priority
    merged_data = merge_deep(original_data, override_data)

    # Return a revalidated model using the original model's class
    return original.__class__(**merged_data)


def merge_deep(original_data: dict, override_data: dict):
    result = deepcopy(original_data)

    def _recursive_merge(_original_data, _override_data):
        for key in _override_data:
            if (
                key in _original_data
                and isinstance(_original_data[key], dict)
                and isinstance(_override_data[key], dict)
            ):
                _recursive_merge(_original_data[key], _override_data[key])
            else:
                _original_data[key] = _override_data[key]

    _recursive_merge(result, override_data)
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
def is_path_within_cwd(path):
    requested_path = os.path.abspath(path)
    return requested_path.startswith(os.path.abspath("."))


async def expire_key(in_dict: dict, dict_key: int | str, wait_time: float | int):
    await asyncio.sleep(wait_time)
    in_dict.pop(dict_key, None)
