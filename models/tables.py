import uuid
from typing import Annotated, Literal, Any, Union
from pydantic import AfterValidator, BaseModel, Field, field_validator
from config import defaults


class TableSearch(BaseModel):
    q: Annotated[Any, AfterValidator(lambda x: str(x))] = ""
    page: Annotated[Any, AfterValidator(lambda x: int(x) if x and x != "" else 1)] = 1
    page_size: Annotated[
        Any,
        AfterValidator(lambda x: int(x) if x and x != "" else defaults.TABLE_PAGE_SIZE),
    ] = defaults.TABLE_PAGE_SIZE
    sorting: tuple = ("created", True)

    @field_validator("sorting", mode="before")
    def split_sorting(cls, v: object) -> object:
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
        }
    )

    return search_model, page, page_size, sort_attr, sort_reverse
