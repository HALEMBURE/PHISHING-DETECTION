import base64
import binascii
import csv
import hashlib
import hmac
import json
import os
import re
import secrets
import threading
import time
from collections import deque
from pathlib import Path
from urllib.parse import urlparse

import joblib
#import chatbot
try:
    import jwt
    from jwt import ExpiredSignatureError, InvalidTokenError
except Exception:
    jwt = None
    ExpiredSignatureError = Exception
    InvalidTokenError = Exception
from fastapi import Depends, FastAPI, Header, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from passlib.context import CryptContext
from pydantic import BaseModel
from sqlalchemy import Column, Integer, String, create_engine
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import declarative_base, sessionmaker

# -----------------------------
# Environment
# -----------------------------
def _load_env_file() -> None:
    env_path = Path(__file__).with_name(".env")
    if not env_path.exists():
        return
    try:
        for raw in env_path.read_text(encoding="utf-8").splitlines():
            line = raw.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            key = key.strip()
            value = value.strip().strip('"').strip("'")
            if key and key not in os.environ:
                os.environ[key] = value
    except Exception as e:
        print("Could not load .env:", e)


_load_env_file()

# -----------------------------
# FastAPI app
# -----------------------------
app = FastAPI()

FRONTEND_ORIGINS = os.environ.get(
    "FRONTEND_ORIGINS",
    "http://127.0.0.1:5500,http://localhost:5500,null",
)
ALLOW_ORIGINS = [o.strip() for o in FRONTEND_ORIGINS.split(",") if o.strip()]
ALLOW_CREDENTIALS = False

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOW_ORIGINS,
    allow_origin_regex=r"^(null|https?://(127\.0\.0\.1|localhost)(:\d+)?)$",
    allow_credentials=ALLOW_CREDENTIALS,
    allow_methods=["*"],
    allow_headers=["*"],
)

# -----------------------------
# Database setup
# -----------------------------
BASE_DIR = os.path.dirname(__file__)
DATABASE_PATH = os.path.join(BASE_DIR, "users.db")
DATABASE_URL = f"sqlite:///{os.path.abspath(DATABASE_PATH)}"
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(bind=engine)
Base = declarative_base()
pwd_context = None
_pwd_init_failed = False
TOKEN_SECRET = os.environ.get("TOKEN_SECRET", "").strip() or secrets.token_urlsafe(48)
JWT_ALGORITHM = "HS256"
PBKDF2_ITERATIONS = 210000
MALICIOUS_PROBA_THRESHOLD = float(os.environ.get("MALICIOUS_PROBA_THRESHOLD", "0.75"))
LOGIN_WINDOW_SECONDS = int(os.environ.get("LOGIN_WINDOW_SECONDS", "60"))
LOGIN_MAX_ATTEMPTS = int(os.environ.get("LOGIN_MAX_ATTEMPTS", "6"))
SIGNUP_WINDOW_SECONDS = int(os.environ.get("SIGNUP_WINDOW_SECONDS", "300"))
SIGNUP_MAX_ATTEMPTS = int(os.environ.get("SIGNUP_MAX_ATTEMPTS", "6"))
_rate_limit_lock = threading.Lock()
_rate_limits: dict[str, deque[float]] = {}

if not os.environ.get("TOKEN_SECRET", "").strip():
    print("TOKEN_SECRET not set; using an ephemeral secret for this process.")
if jwt is None:
    print("PyJWT not installed; using legacy token fallback.")


def get_pwd_context():
    global pwd_context, _pwd_init_failed
    if pwd_context is not None or _pwd_init_failed:
        return pwd_context
    try:
        pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
        return pwd_context
    except Exception as e:
        print("Could not initialize bcrypt CryptContext:", e)
        _pwd_init_failed = True
        pwd_context = None
        return None


# -----------------------------
# User model
# -----------------------------
class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String)
    email = Column(String, unique=True)
    password = Column(String)


class ChatMessage(Base):
    __tablename__ = "chat_messages"

    id = Column(Integer, primary_key=True, index=True)
    user_email = Column(String, index=True)
    role = Column(String)
    content = Column(String)
    ts = Column(Integer)


Base.metadata.create_all(bind=engine)


class AuthPayload(BaseModel):
    name: str | None = None
    email: str
    password: str


class TokenPayload(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user_email: str
    user_name: str


# -----------------------------
# Password helpers
# -----------------------------
def hash_password(password: str) -> str:
    # Truncate to bcrypt input length limit.
    pw = password[:72]
    ctx = get_pwd_context()
    if ctx:
        try:
            return ctx.hash(pw)
        except Exception as e:
            print("bcrypt hash failed, using PBKDF2 fallback:", e)

    salt = binascii.hexlify(os.urandom(16)).decode()
    dk = hashlib.pbkdf2_hmac("sha256", pw.encode(), salt.encode(), PBKDF2_ITERATIONS)
    return f"pbkdf2_sha256${PBKDF2_ITERATIONS}${salt}${binascii.hexlify(dk).decode()}"


def verify_password(plain: str, hashed: str) -> bool:
    pw = plain[:72]
    ctx = get_pwd_context()
    if ctx:
        try:
            return ctx.verify(pw, hashed)
        except Exception:
            pass

    if not isinstance(hashed, str) or not hashed.startswith("pbkdf2_sha256$"):
        return False

    parts = hashed.split("$")
    if len(parts) == 4:
        _, iter_s, salt, expected = parts
        iterations = int(iter_s)
        dk = hashlib.pbkdf2_hmac("sha256", pw.encode(), salt.encode(), iterations)
        return hmac.compare_digest(binascii.hexlify(dk).decode(), expected)

    # Backward compatibility for legacy hashes.
    if len(parts) == 2:
        expected = parts[1]
        legacy_salt = os.environ.get("PWD_SALT", "phish_salt").encode()
        dk = hashlib.pbkdf2_hmac("sha256", pw.encode(), legacy_salt, 100000)
        return hmac.compare_digest(binascii.hexlify(dk).decode(), expected)

    return False


def _b64url_encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode()


def _b64url_decode(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(value + padding)


def create_access_token(email: str, name: str, expires_in: int = 3600) -> str:
    payload = {
        "sub": email,
        "name": name or "",
        "exp": int(time.time()) + expires_in,
    }
    if jwt is not None:
        token = jwt.encode(payload, TOKEN_SECRET, algorithm=JWT_ALGORITHM)
        if isinstance(token, bytes):
            token = token.decode()
        return token

    payload_part = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    sig = hmac.new(TOKEN_SECRET.encode(), payload_part.encode(), hashlib.sha256).digest()
    sig_part = _b64url_encode(sig)
    return f"{payload_part}.{sig_part}"


def verify_access_token(token: str) -> dict:
    if jwt is not None:
        try:
            payload = jwt.decode(token, TOKEN_SECRET, algorithms=[JWT_ALGORITHM])
            if not payload.get("sub"):
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")
            return payload
        except ExpiredSignatureError:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token expired")
        except InvalidTokenError:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")
        except HTTPException:
            raise
        except Exception:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")

    try:
        payload_part, sig_part = token.split(".", 1)
    except ValueError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")

    expected_sig = hmac.new(TOKEN_SECRET.encode(), payload_part.encode(), hashlib.sha256).digest()
    try:
        given_sig = _b64url_decode(sig_part)
    except Exception:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")

    if not hmac.compare_digest(expected_sig, given_sig):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")

    try:
        payload = json.loads(_b64url_decode(payload_part).decode())
    except Exception:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")

    if int(payload.get("exp", 0)) < int(time.time()):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token expired")

    return payload


def get_current_user(authorization: str | None = Header(default=None)) -> dict:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing token")
    token = authorization.split(" ", 1)[1].strip()
    return verify_access_token(token)


EMAIL_REGEX = re.compile(r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$")
HOST_REGEX = re.compile(r"^[a-z0-9.-]+$")


def validate_email(email: str) -> str:
    cleaned = (email or "").strip().lower()
    if not cleaned or not EMAIL_REGEX.match(cleaned):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid email format")
    return cleaned


def validate_password_strength(password: str) -> str:
    pw = (password or "").strip()
    if len(pw) < 8 or len(pw) > 128:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Password must be between 8 and 128 characters",
        )
    if not re.search(r"[A-Z]", pw):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Password must include at least one uppercase letter",
        )
    if not re.search(r"[a-z]", pw):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Password must include at least one lowercase letter",
        )
    if not re.search(r"\d", pw):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Password must include at least one number",
        )
    return pw


def validate_name(name: str | None) -> str:
    cleaned = (name or "").strip()
    if len(cleaned) > 100:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Name is too long")
    return cleaned


def _rate_limit_key(endpoint: str, identity: str) -> str:
    return f"{endpoint}:{identity.strip().lower() or 'anonymous'}"


def check_rate_limit(endpoint: str, identity: str, window_seconds: int, max_attempts: int):
    now = time.time()
    key = _rate_limit_key(endpoint, identity)
    with _rate_limit_lock:
        q = _rate_limits.setdefault(key, deque())
        while q and q[0] <= now - window_seconds:
            q.popleft()
        if len(q) >= max_attempts:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Too many requests, please retry later",
            )
        q.append(now)


def client_identity(ip_header: str | None, fallback: str, user_hint: str = "") -> str:
    header_value = (ip_header or "").split(",")[0].strip()
    identity = header_value or fallback or "unknown"
    if user_hint:
        identity = f"{identity}|{user_hint.strip().lower()}"
    return identity


chatbot.register_chat_routes(
    app=app,
    get_current_user=get_current_user,
    check_rate_limit=check_rate_limit,
    client_identity=client_identity,
    db_session_factory=SessionLocal,
    ChatMessage=ChatMessage,
)


# -----------------------------
# Signup endpoint
# -----------------------------
@app.post("/signup")
def signup(user: AuthPayload, x_forwarded_for: str | None = Header(default=None)):
    db = SessionLocal()
    try:
        cleaned_email = validate_email(user.email)
        check_rate_limit(
            endpoint="signup",
            identity=client_identity(x_forwarded_for, "unknown", cleaned_email),
            window_seconds=SIGNUP_WINDOW_SECONDS,
            max_attempts=SIGNUP_MAX_ATTEMPTS,
        )
        validate_password_strength(user.password)
        cleaned_name = validate_name(user.name)
        existing_user = db.query(User).filter(User.email == cleaned_email).first()
        if existing_user:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="User already exists",
            )

        new_user = User(
            name=cleaned_name,
            email=cleaned_email,
            password=hash_password(user.password),
        )

        db.add(new_user)
        db.commit()
        return {"message": "Signup successful"}
    except IntegrityError:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="User already exists",
        )
    except HTTPException:
        raise
    except Exception as e:
        db.rollback()
        print("Signup error:", e)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Signup failed",
        )
    finally:
        db.close()


# -----------------------------
# Login endpoint
# -----------------------------
@app.post("/login")
def login(user: AuthPayload, x_forwarded_for: str | None = Header(default=None)) -> TokenPayload:
    db = SessionLocal()
    try:
        cleaned_email = validate_email(user.email)
        check_rate_limit(
            endpoint="login",
            identity=client_identity(x_forwarded_for, "unknown", cleaned_email),
            window_seconds=LOGIN_WINDOW_SECONDS,
            max_attempts=LOGIN_MAX_ATTEMPTS,
        )
        password = (user.password or "").strip()
        if not password:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Password is required",
            )
        db_user = db.query(User).filter(User.email == cleaned_email).first()
        if not db_user or not verify_password(password, db_user.password):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid credentials",
            )

        token = create_access_token(db_user.email, (db_user.name or "").strip())
        return TokenPayload(
            access_token=token,
            token_type="bearer",
            user_email=db_user.email,
            user_name=(db_user.name or "").strip(),
        )
    except HTTPException:
        raise
    except Exception as e:
        print("Login error:", e)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Login failed",
        )
    finally:
        db.close()


# -----------------------------
# Load trained model
# -----------------------------
MODEL_PATH = os.path.join(
    os.path.dirname(__file__),
    "..",
    "MODEL",
    "model.pkl",
)
MODEL_PATH = os.path.abspath(MODEL_PATH)
model = None
try:
    model = joblib.load(MODEL_PATH)
    print("Model loaded successfully")
except Exception as e:
    print("Model load failed:", e)
    model = None


# -----------------------------
# CSV log setup
# -----------------------------
LOG_FILE = os.path.join(os.path.dirname(__file__), "prediction_log.csv")
if not os.path.exists(LOG_FILE):
    with open(LOG_FILE, mode="w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["url", "features", "prediction", "source", "probability"])


# -----------------------------
# Input schema
# -----------------------------
class URLItem(BaseModel):
    url: str


# -----------------------------
# Feature extraction
# -----------------------------
def extract_features(url: str):
    parsed = urlparse(url)
    domain = parsed.netloc
    path = parsed.path
    return [
        len(url),
        len(domain),
        1 if re.match(r"\d+\.\d+\.\d+\.\d+", domain) else 0,
        url.count("."),
        domain.count("."),
        1 if "@" in url else 0,
        url.count("-"),
        sum(c.isdigit() for c in url),
        1 if parsed.scheme == "https" else 0,
        1
        if any(word in url.lower() for word in ["login", "verify", "update", "bank", "secure", "free", "bonus"])
        else 0,
        1 if "//" in path else 0,
    ]


def normalize_url(raw_url: str) -> str:
    url = raw_url.strip()
    if not url:
        return ""
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", url):
        url = "http://" + url
    return url


def validate_scan_url(url: str) -> str:
    parsed = urlparse(url)
    if parsed.scheme.lower() not in {"http", "https"}:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Only http and https URLs are supported",
        )
    host = (parsed.hostname or "").strip().lower()
    if not host:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid URL")
    if not HOST_REGEX.match(host):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid URL host")
    return url


# -----------------------------
# Rule-based detection
# -----------------------------
def rule_check(url: str):
    parsed = urlparse(url)
    domain = (parsed.hostname or parsed.netloc or "").lower()
    if "@" in url or re.match(r"^\d+\.\d+\.\d+\.\d+$", domain):
        return "malicious"

    whitelist = ["google.com", "youtube.com", "github.com"]
    if any(domain == w or domain.endswith("." + w) for w in whitelist):
        return "safe"

    return None


# -----------------------------
# Predict endpoint
# -----------------------------
@app.post("/predict")
def predict(item: URLItem, current_user: dict = Depends(get_current_user)):
    url = normalize_url(item.url)
    if not url:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Empty URL",
        )
    validate_scan_url(url)

    try:
        rule_result = rule_check(url)
        if rule_result:
            result = rule_result
            source = "rule"
            probability = 1.0 if result == "malicious" else 0.0
            features_to_log = []
        else:
            if model is None:
                raise HTTPException(
                    status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                    detail="Model is not available. Load or retrain model first.",
                )
            features_to_log = extract_features(url)
            source = "model"

            if hasattr(model, "predict_proba"):
                proba = model.predict_proba([features_to_log])[0]
                classes = [str(c).lower() for c in getattr(model, "classes_", [])]
                if "malicious" in classes:
                    malicious_idx = classes.index("malicious")
                    malicious_proba = float(proba[malicious_idx])
                    probability = malicious_proba
                    result = "malicious" if malicious_proba >= MALICIOUS_PROBA_THRESHOLD else "benign"
                else:
                    probability = float(max(proba))
                    result = model.predict([features_to_log])[0]
            else:
                probability = 1.0
                result = model.predict([features_to_log])[0]

        with open(LOG_FILE, mode="a", newline="") as f:
            writer = csv.writer(f)
            writer.writerow([url, features_to_log, result, source, probability])

        return {
            "url": url,
            "prediction": result,
            "source": source,
            "probability": probability,
        }
    except HTTPException:
        raise
    except Exception as e:
        print("Predict error:", e)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Prediction failed",
        )
