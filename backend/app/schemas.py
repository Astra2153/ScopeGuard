from pydantic import BaseModel, ConfigDict, Field

EMAIL_PATTERN = r"^[^@\s]+@[^@\s]+\.[^@\s]+$"


class RegisterIn(BaseModel):
    # extra="forbid" rejects unknown fields, so nobody can send role="admin"
    model_config = ConfigDict(extra="forbid")

    email: str = Field(max_length=320, pattern=EMAIL_PATTERN)
    password: str = Field(min_length=12, max_length=128)


class LoginIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    email: str = Field(max_length=320)
    password: str = Field(max_length=128)
