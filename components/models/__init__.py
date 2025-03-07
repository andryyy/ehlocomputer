import email_validator
from pydantic import (
    Field,
    BaseModel,
    IPvAnyAddress,
    computed_field,
    AfterValidator,
    BeforeValidator,
    model_validator,
    field_validator,
    constr,
    conint,
    TypeAdapter,
    ConfigDict,
    ValidationError,
    validate_call,
)
from pydantic_core import PydanticCustomError
from typing import List, Dict, Any, Literal, Annotated
from uuid import UUID, uuid4

email_validator.TEST_ENVIRONMENT = True
validate_email = email_validator.validate_email
