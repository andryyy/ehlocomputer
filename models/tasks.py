from pydantic import BaseModel, Field, field_validator, ValidationError
from typing import List, Dict, Any, Literal

CLUSTER_TASKS = [
    "users_create_user",
    "users_create_credential",
    "users_user_patch",
    "users_user_patch_profile",
    "users_user_patch_credential",
    "users_user_delete",
    "users_user_delete_credential",
    "objects_object_create",
    "objects_object_patch",
    "objects_object_delete",
]


class TaskModel(BaseModel):
    command: Literal["TASK", "RTASK"]
    name: str = Literal[*CLUSTER_TASKS]
    kwargs: List[Dict[str, Any]] = Field(
        description="List containing exactly two dictionaries"
    )

    @field_validator("kwargs")
    def validate_kwargs_length(cls, v):
        if len(v) != 2:
            raise ValueError("kwargs must contain exactly two dictionaries.")
        if not all(isinstance(item, dict) for item in v):
            raise ValueError("All items in the kwargs must be dictionaries.")
        return v

    @classmethod
    def parse_raw_task(cls, raw_data: str) -> "TaskModel":
        from json import loads

        task_parts = raw_data.split(" ", 2)

        if len(task_parts) != 3:
            raise ValueError(
                "Input does not follow the 'TASK|RTASK <name> [json]' format."
            )

        command, name, json_kwargs = task_parts
        kwargs = loads(json_kwargs)
        return cls(command=command, name=name, kwargs=kwargs)
