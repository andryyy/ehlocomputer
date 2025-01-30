import uuid
from typing import Annotated, Literal, Any, Union
from pydantic import AfterValidator, BaseModel, Field, field_validator
from config import defaults
from utils.helpers import ensure_list, to_unique_sorted_str_list


class TableSearch(BaseModel):
    q: Annotated[Any, AfterValidator(lambda x: str(x))] = ""
    page: Annotated[Any, AfterValidator(lambda x: int(x) if x else 1)] = 1
    page_size: Annotated[
        Any,
        AfterValidator(lambda x: int(x) if x else defaults.TABLE_PAGE_SIZE),
    ] = defaults.TABLE_PAGE_SIZE
    sorting: tuple = ("created", True)
    filters: Annotated[
        Any,
        AfterValidator(lambda x: to_unique_sorted_str_list(ensure_list(x))),
    ] = {}

    @field_validator("filters", mode="after")
    def filters_formatter(cls, v):
        filters = dict()
        for f in v:
            key_name, key_value = f.split(":")
            if key_name == "assigned_users":
                continue
            if key_name not in filters.keys():
                filters[key_name] = key_value
            else:
                if isinstance(filters[key_name], list):
                    filters[key_name].append(key_value)
                else:
                    filters[key_name] = [filters[key_name], key_value]

        return filters

    @field_validator("sorting", mode="before")
    def split_sorting(cls, v):
        if isinstance(v, str):
            match v.split(":"):
                case [
                    sort_attr,
                    direction,
                ]:
                    sort_reverse = True if direction == "desc" else False
                case _:
                    sort_reverse = True
                    sort_attr = "created"

            return (sort_attr, sort_reverse)


def TableSearchHelper(body, session_key_identifier, default_sort_attr):
    from quart import session

    search_model = TableSearch.parse_obj(body or {})
    search_model_post = search_model.dict(exclude_unset=True)

    # Post wins over session wins over default
    page = search_model_post.get(
        "page", session.get(f"{session_key_identifier}_page", search_model.page)
    )
    page_size = search_model_post.get(
        "page_size",
        session.get(f"{session_key_identifier}_page_size", search_model.page_size),
    )
    filters = search_model_post.get(
        "filters",
        session.get(f"{session_key_identifier}_filters", search_model.filters),
    )
    sorting = search_model_post.get(
        "sorting",
        session.get(f"{session_key_identifier}_sorting", (default_sort_attr, False)),
    )
    sort_attr, sort_reverse = sorting

    session.update(
        {
            f"{session_key_identifier}_page": page,
            f"{session_key_identifier}_page_size": page_size,
            f"{session_key_identifier}_sorting": sorting,
            f"{session_key_identifier}_filters": filters,
        }
    )

    return search_model, page, page_size, sort_attr, sort_reverse, filters
