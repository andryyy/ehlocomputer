from pydantic import BaseModel, Field, field_validator, ValidationError
from typing import List, Dict, Any, Literal


class TaskModel(BaseModel):
    command: Literal["TASK"] = Field(description="Must be 'TASK'")
    init_kwargs: str = Field(description="init_kwargs following TASK")
    task_kwargs: List[Dict[str, Any]] = Field(
        description="List containing exactly two dictionaries"
    )

    @field_validator("task_kwargs")
    def validate_task_kwargs_length(cls, v):
        if len(v) != 2:
            raise ValueError("task_kwargs must contain exactly two dictionaries.")
        if not all(isinstance(item, dict) for item in v):
            raise ValueError("All items in the task_kwargs must be dictionaries.")
        return v

    @classmethod
    def parse_raw_task(cls, raw_data: str) -> "TaskModel":
        # Split the command string and parse JSON-like part
        task_parts = raw_data.split(" ", 2)
        if len(task_parts) != 3:
            raise ValueError(
                "Input does not follow the 'TASK <init_kwargs> [json]' format."
            )

        command, init_kwargs, json_task_kwargs = task_parts
        if command != "TASK":
            raise ValueError("Input must start with 'TASK'.")

        # Parse JSON task_kwargs
        from json import loads

        task_kwargs = loads(json_task_kwargs)

        # Validate the complete structure with Pydantic
        return cls(command=command, init_kwargs=init_kwargs, task_kwargs=task_kwargs)
