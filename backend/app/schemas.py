from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

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


def _not_blank(value: str) -> str:
    value = value.strip()
    if not value:
        raise ValueError("must not be blank")
    return value


class EngagementIn(BaseModel):
    model_config = ConfigDict(extra="forbid")  # owner_id can never come from the client

    name: str = Field(min_length=1, max_length=200)

    _strip = field_validator("name")(_not_blank)


class FindingIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    title: str = Field(min_length=1, max_length=300)
    severity: Literal["info", "low", "medium", "high", "critical"] = "info"
    description: str = Field(default="", max_length=10000)

    _strip = field_validator("title")(_not_blank)


class FindingStatusIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status: Literal["open", "fixed", "partially_fixed", "not_fixed"]
