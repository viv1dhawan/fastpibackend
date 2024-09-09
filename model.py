from pydantic import BaseModel, EmailStr
from sqlalchemy import Column, Integer, String, Boolean
from sqlalchemy.ext.declarative import declarative_base
from typing import Optional

Base = declarative_base()

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True)
    user_name = Column(String)
    first_name = Column(String)
    last_name = Column(String)
    hashed_password = Column(String)
    is_active = Column(Boolean, default=False)
    reset_token = Column(String, nullable=True)
    reset_token_expiry = Column(Integer, nullable=True)

class UserCreate(BaseModel):
    email: EmailStr
    user_name: str
    first_name: str
    last_name: str
    password: str

class UserLogin(BaseModel):
    email: EmailStr
    password: str

class UserForgetPassword(BaseModel):
    email: EmailStr

class UserResetPassword(BaseModel):
    reset_token: str
    new_password: str
    confirm_password: str

    @classmethod
    def validate(cls, values):
        if values['new_password'] != values['confirm_password']:
            raise ValueError('New password and confirm password do not match')
        return values

class UserVerify(BaseModel):
    email: EmailStr
    verification_code: str
