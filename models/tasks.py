from pydantic import BaseModel, Field, field_validator, ValidationError
from typing import List, Dict, Any, Literal


class TaskModel(BaseModel):
    command: Literal["TASK"] = Field(description="Must be 'TASK'")
    init_data: str = Field(description="init_data following TASK")
    payload: List[Dict[str, Any]] = Field(
        description="List containing exactly two dictionaries"
    )

    @field_validator("payload")
    def validate_payload_length(cls, v):
        if len(v) != 2:
            raise ValueError("Payload must contain exactly two dictionaries.")
        if not all(isinstance(item, dict) for item in v):
            raise ValueError("All items in the payload must be dictionaries.")
        return v

    @classmethod
    def parse_raw_task(cls, raw_data: str) -> "TaskModel":
        # Split the command string and parse JSON-like part
        task_parts = raw_data.split(" ", 2)
        if len(task_parts) != 3:
            raise ValueError(
                "Input does not follow the 'TASK <init_data> [json]' format."
            )

        command, init_data, json_payload = task_parts
        if command != "TASK":
            raise ValueError("Input must start with 'TASK'.")

        # Parse JSON payload
        from json import loads

        payload = loads(json_payload)

        # Validate the complete structure with Pydantic
        return cls(command=command, init_data=init_data, payload=payload)
