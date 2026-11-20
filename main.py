from fastapi import FastAPI, Request, Form, Depends,HTTPException
from fastapi.responses import RedirectResponse, Response
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from starlette.middleware.sessions import SessionMiddleware
from dotenv import load_dotenv
import os
from sqlalchemy.orm import Session
from database import engine, Base, get_db
from models import User
from pwdlib import PasswordHash


load_dotenv(".env.local")

Base.metadata.create_all(bind=engine)

app = FastAPI()

templates = Jinja2Templates(directory="templates")

app.mount(
    "/static",
    StaticFiles(directory="static"),
    name="static"
)

app.add_middleware(
    SessionMiddleware,
    secret_key=os.getenv("SESSION_SECRET"),
    same_site="lax",
    https_only=False
)


@app.get("/")
def home(request: Request):
    return templates.TemplateResponse(
        request=request,
        name="index.html"
    )


@app.get("/register")
def register_page(request: Request):
    return templates.TemplateResponse(
        request=request,
        name="register.html"
    )


password_hash = PasswordHash.recommended()

def hash_password(password: str):
    return password_hash.hash(password)

def verify_password(password: str, hashed_password: str):
    return password_hash.verify(password, hashed_password)


@app.post("/register")
def register(
    name: str = Form(...),
    email: str = Form(...),
    password: str = Form(...),
    db: Session = Depends(get_db)
):
    existing_user = db.query(User).filter(
        User.email == email
    ).first()

    if existing_user:
        return {"error": "Email already registered"}

    hashed_password = hash_password(password)

    new_user = User(
        name=name,
        email=email,
        password_hash=hashed_password,
        role="student"
    )

    db.add(new_user)
    db.commit()

    return RedirectResponse("/login", status_code=303)

@app.get("/login")
def login_page(request: Request):
    return templates.TemplateResponse(
        request=request,
        name="login.html"
    )

@app.post("/login")
def login(
    request: Request,
    email: str = Form(...),
    password: str = Form(...),
    db: Session = Depends(get_db)
):
    user = db.query(User).filter(
        User.email == email
    ).first()

    if not user:
        return {"error": "Invalid email or password"}

    if not verify_password(password, user.password_hash):
        return {"error": "Invalid email or password"}

    request.session["user_id"] = user.id

    return RedirectResponse(
        url="/dashboard",
        status_code=303
    )

def get_current_user(
    request: Request,
    db: Session = Depends(get_db)
):
    user_id = request.session.get("user_id")

    if not user_id:
        raise HTTPException(
            status_code=401,
            detail="Not authenticated"
        )

    user = db.query(User).filter(
        User.id == user_id
    ).first()

    if not user:
        request.session.clear()
        raise HTTPException(
            status_code=401,
            detail="User not found"
        )

    return user
@app.get("/dashboard")
def dashboard(
    current_user: User = Depends(get_current_user)
):
    return {
        "message": "Authentication successful",
        "name": current_user.name
    }
