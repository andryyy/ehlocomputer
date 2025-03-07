from components.database import IN_MEMORY_DB
from components.models import UUID, validate_call
from components.utils import ensure_list


@validate_call
def buster(object_id: UUID | list[UUID]):
    object_ids = ensure_list(object_id)
    for object_id in object_ids:
        object_id = str(object_id)

        for user_id in IN_MEMORY_DB["OBJECTS_CACHE"]:
            cached_keys = list(IN_MEMORY_DB["OBJECTS_CACHE"][user_id].keys())
            if object_id in cached_keys:
                mapping_name = IN_MEMORY_DB["OBJECTS_CACHE"][user_id][object_id].name
                if object_id in IN_MEMORY_DB["OBJECTS_CACHE"][user_id]:
                    del IN_MEMORY_DB["OBJECTS_CACHE"][user_id][object_id]

        for user_id in IN_MEMORY_DB["FORM_OPTIONS_CACHE"]:
            for option in IN_MEMORY_DB["FORM_OPTIONS_CACHE"][user_id].copy():
                if any(
                    d["value"] == object_id
                    for d in IN_MEMORY_DB["FORM_OPTIONS_CACHE"][user_id][option]
                ):
                    del IN_MEMORY_DB["FORM_OPTIONS_CACHE"][user_id][option]
