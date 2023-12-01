from email_validator import validate_email
from pydantic import BaseModel, validator
from pydantic_core import PydanticCustomError


class PatchUser(BaseModel):
    @validator("email", pre=True)
    def _user_exists(cls, v):
        if v in [None, ""]:
            return ""
        try:
            email = validate_email(v, check_deliverability=False).ascii_email
        except:
            raise PydanticCustomError(
                "email_invalid",
                "The provided email address is invalid",
                dict(provided_email=v),
            )
        return email

    email: str
