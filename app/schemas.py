"""
Schémas Pydantic. La validation stricte ici est la première ligne de
défense contre l'injection et le XSS (OWASP A03) : un nom d'utilisateur
qui ne matche pas le pattern autorisé, ou un mot de passe trop court,
est rejeté avant même d'atteindre la base de données.
"""
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
                "Le nom d'utilisateur doit contenir entre 3 et 50 caractères "
                "alphanumériques, points, tirets ou underscores uniquement."
            )
        return v

    @field_validator("password")
    @classmethod
    def password_must_be_strong(cls, v: str) -> str:
        if len(v) < 10:
            raise ValueError("Le mot de passe doit contenir au moins 10 caractères.")
        if not re.search(r"[A-Z]", v) or not re.search(r"[a-z]", v) or not re.search(r"\d", v):
            raise ValueError(
                "Le mot de passe doit contenir au moins une majuscule, "
                "une minuscule et un chiffre."
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
            raise ValueError("Le titre doit contenir entre 1 et 200 caractères.")
        return v

    @field_validator("content")
    @classmethod
    def content_length(cls, v: str) -> str:
        if not (1 <= len(v) <= 10_000):
            raise ValueError("Le contenu doit contenir entre 1 et 10 000 caractères.")
        return v


class NoteOut(BaseModel):
    id: int
    title: str
    content: str
    owner_id: int

    class Config:
        from_attributes = True
