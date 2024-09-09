from fastapi import FastAPI, Depends, HTTPException
from fastapi.security import OAuth2PasswordBearer
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from model import UserCreate, UserForgetPassword, UserLogin, UserResetPassword, UserVerify, User
from db import create_user, authenticate_user, generate_reset_token, reset_password, verify_user, generate_verification_code, get_user
from database import get_db
from pydantic import BaseModel
import jwt
from jose import JWTError
from passlib.context import CryptContext
from datetime import datetime, timedelta
from typing import Optional
from model import User
from database import Base, engine

app = FastAPI()

# Create all tables based on the imported models
Base.metadata.create_all(bind=engine)

# Serve static files from the 'static' directory
app.mount("/static", StaticFiles(directory="static"), name="static")

pwd_context = CryptContext(schemes=["bcrypt"], default="bcrypt")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

SECRET_KEY = "your_secret_key_here"
ALGORITHM = "HS256"

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

@app.post("/signup")
async def signup(user: UserCreate, db: get_db = Depends()):
    db_user = create_user(db, user)
    verification_code = generate_verification_code()
    # Here you should send the verification code to the user's email.
    # Example: send_verification_email(user.email, verification_code)
    return {"message": "User created successfully"}

@app.post("/login")
async def login(user: UserLogin, db: get_db = Depends()):
    db_user = authenticate_user(db, user)
    if db_user:
        if db_user.is_active:
            access_token_expires = timedelta(minutes=15)
            access_token = create_access_token(
                data={"sub": db_user.email}, expires_delta=access_token_expires
            )
            return {"access_token": access_token, "token_type": "bearer"}
        else:
            raise HTTPException(status_code=403, detail="User is not verified")
    else:
        raise HTTPException(status_code=401, detail="Invalid email or password")

@app.post("/reset-password")
async def reset_password_endpoint(user: UserResetPassword, db: get_db = Depends()):
    if reset_password(db, user):
        return {"message": "Password reset successfully"}
    else:
        raise HTTPException(status_code=404, detail="Invalid reset token or user not found")

@app.post("/forget-password")
async def forget_password(user: UserForgetPassword, db: get_db = Depends()):
    reset_token = generate_reset_token(db, user)
    if reset_token:
        # Here you should send the reset token to the user's email.
        # Example: send_reset_token_email(user.email, reset_token)
        return {"message": "Reset token sent successfully"}
    else:
        raise HTTPException(status_code=404, detail="User not found")

@app.post("/verify-account")
async def verify_account(user: UserVerify, db: get_db = Depends()):
    if verify_user(db, user):
        return {"message": "Account verified successfully"}
    else:
        raise HTTPException(status_code=404, detail="User not found")

async def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=401,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    user = get_user(email=email, db=Depends(get_db))  # Retrieve user from database
    if user is None:
        raise credentials_exception
    return user

@app.get("/protected")
async def protected_route(user: User = Depends(get_current_user)):
    return {"message": f"Hello, {user.email}!"}

@app.get("/", response_class=HTMLResponse)
async def read_index():
    with open("static/index.html") as f:
        content = f.read()
    return HTMLResponse(content=content)

@app.get("/login-page", response_class=HTMLResponse)
async def read_login_page():
    with open("static/login.html") as f:
        content = f.read()
    return HTMLResponse(content=content)

@app.get("/signup-page", response_class=HTMLResponse)
async def read_signup_page():
    with open("static/signup.html") as f:
        content = f.read()
    return HTMLResponse(content=content)

@app.get("/forget-password-page", response_class=HTMLResponse)
async def read_forget_password_page():
    with open("static/forget-password.html") as f:
        content = f.read()
    return HTMLResponse(content=content)

@app.get("/reset-password-page", response_class=HTMLResponse)
async def read_reset_password_page():
    with open("static/reset-password.html") as f:
        content = f.read()
    return HTMLResponse(content=content)

@app.get("/verify-account-page", response_class=HTMLResponse)
async def read_verify_account_page():
    with open("static/verify-account.html") as f:
        content = f.read()
    return HTMLResponse(content=content)

@app.get("/about-page", response_class=HTMLResponse)
async def read_about_page():
    with open("static/about.html") as f:
        content = f.read()
    return HTMLResponse(content=content)
