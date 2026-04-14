from pydantic import BaseModel, EmailStr, Field
from typing import Optional
from datetime import datetime

# ============= USER SCHEMAS =============

class UserBase(BaseModel):
    email: EmailStr

class UserCreate(UserBase):
    password: str = Field(..., min_length=6)

class UserLogin(BaseModel):
    email: EmailStr
    password: str

class UserResponse(UserBase):
    id: int
    created_at: datetime

    class Config:
        from_attributes = True

# ============= CLIENT SCHEMAS =============

class ClientBase(BaseModel):
    name: str = Field(..., min_length=1, max_length=100)
    surname: str = Field(..., min_length=1, max_length=100)
    age: Optional[int] = None
    dni: str = Field(..., min_length=8, max_length=8, pattern=r"^\d{8}$")
    phone: str = Field(..., min_length=9, max_length=9, pattern=r"^\d{9}$")
    email: Optional[str] = None
    address: Optional[str] = None

class ClientCreate(ClientBase):
    pass

class ClientResponse(ClientBase):
    id: int
    user_id: int
    created_at: datetime

    class Config:
        from_attributes = True

class ClientListResponse(BaseModel):
    clients: list[ClientResponse]
    total: int

# ============= AUTH RESPONSE =============

class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: UserResponse

class LoginResponse(BaseModel):
    message: str
    access_token: str
    token_type: str
    user: UserResponse
