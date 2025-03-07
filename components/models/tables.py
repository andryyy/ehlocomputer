from config import defaults
from components.utils import ensure_list, to_unique_sorted_str_list
from components.models import *


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
