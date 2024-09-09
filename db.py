from pydantic import BaseModel
from sqlalchemy.orm import Session
from model import User, UserCreate, UserVerify, UserLogin, UserResetPassword, UserForgetPassword
from database import get_db
from passlib.context import CryptContext
from typing import Optional
import random
import string
import time

pwd_context = CryptContext(schemes=["bcrypt"], default="bcrypt")

# Get user by ID
def get_user(db: Session, user_id: int):
    return db.query(User).filter(User.id == user_id).first()

# Get user by email
def get_user_by_email(db: Session, email: str):
    return db.query(User).filter(User.email == email).first()

# Create a new user
def create_user(db: Session, user: UserCreate):
    hashed_password = pwd_context.hash(user.password)
    db_user = User(
        email=user.email,
        user_name=user.user_name,
        first_name=user.first_name,
        last_name=user.last_name,
        hashed_password=hashed_password
    )
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user

# Verify user
def verify_user(db: Session, user: UserVerify):
    db_user = get_user_by_email(db, user.email)
    if db_user:
        # Verification logic here, assuming the verification_code is correct
        db_user.is_active = True
        db.commit()
        return True
    return False

# Reset user password
def reset_password(db: Session, user: UserResetPassword):
    db_user = get_user_by_email(db, user.email)
    if db_user and db_user.reset_token == user.reset_token and db_user.reset_token_expiry > int(time.time()):
        hashed_password = pwd_context.hash(user.new_password)
        db_user.hashed_password = hashed_password
        db_user.reset_token = None
        db_user.reset_token_expiry = None
        db.commit()
        return True
    return False

# Authenticate user
def authenticate_user(db: Session, user: UserLogin):
    db_user = get_user_by_email(db, user.email)
    if db_user and pwd_context.verify(user.password, db_user.hashed_password):
        return db_user
    return None

# Generate a verification code
def generate_verification_code():
    return ''.join(random.choices(string.ascii_uppercase + string.digits, k=6))

# Generate a reset token and set an expiration time (e.g., 1 hour)
def generate_reset_token(db: Session, user: UserForgetPassword):
    db_user = get_user_by_email(db, user.email)
    if db_user:
        reset_token = ''.join(random.choices(string.ascii_letters + string.digits, k=32))
        db_user.reset_token = reset_token
        db_user.reset_token_expiry = int(time.time()) + 3600  # Token expires in 1 hour
        db.commit()
        return reset_token
    return None

# Ensure the new password and confirm password match
class UserResetPassword(BaseModel):
    reset_token: str
    new_password: str
    confirm_password: str

    @classmethod
    def validate(cls, values):
        if values['new_password'] != values['confirm_password']:
            raise ValueError('New password and confirm password do not match')
        return values
