import email_validator
from pydantic import (
    AfterValidator,
    BaseModel,
    BeforeValidator,
    computed_field,
    ConfigDict,
    conint,
    constr,
    Field,
    field_validator,
    FilePath,
    IPvAnyAddress,
    model_validator,
    TypeAdapter,
    validate_call,
    ValidationError,
)
from pydantic_core import PydanticCustomError
from typing import List, Dict, Any, Literal, Annotated
from uuid import UUID, uuid4

email_validator.TEST_ENVIRONMENT = True
validate_email = email_validator.validate_email
