"""Pydantic schemas. Strict validation here is the first line of defense
against injection and XSS (OWASP A03) — bad input never reaches the database."""
import re

from pydantic import BaseModel, EmailStr, field_validator

USERNAME_PATTERN = re.compile(r"^[a-zA-Z0-9_.-]{3,50}$")


class UserCreate(BaseModel):
    username: str
    email: EmailStr
    password: str

    @field_validator("username")
    @classmethod
    def username_must_be_safe(cls, v: str) -> str:
        if not USERNAME_PATTERN.match(v):
            raise ValueError(
                "Username must be 3-50 characters: letters, digits, "
                "dots, hyphens or underscores only."
            )
        return v

    @field_validator("password")
    @classmethod
    def password_must_be_strong(cls, v: str) -> str:
        if len(v) < 10:
            raise ValueError("Password must be at least 10 characters.")
        if not re.search(r"[A-Z]", v) or not re.search(r"[a-z]", v) or not re.search(r"\d", v):
            raise ValueError(
                "Password must contain at least one uppercase letter, "
                "one lowercase letter, and one digit."
            )
        return v


class UserOut(BaseModel):
    id: int
    username: str
    email: EmailStr

    class Config:
        from_attributes = True


class UserLogin(BaseModel):
    username: str
    password: str


class Token(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"


class TokenRefreshRequest(BaseModel):
    refresh_token: str


class NoteCreate(BaseModel):
    title: str
    content: str

    @field_validator("title")
    @classmethod
    def title_length(cls, v: str) -> str:
        if not (1 <= len(v) <= 200):
            raise ValueError("Title must be 1-200 characters.")
        return v

    @field_validator("content")
    @classmethod
    def content_length(cls, v: str) -> str:
        if not (1 <= len(v) <= 10_000):
            raise ValueError("Content must be 1-10,000 characters.")
        return v


class NoteOut(BaseModel):
    id: int
    title: str
    content: str
    owner_id: int

    class Config:
        from_attributes = True
