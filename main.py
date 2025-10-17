import os
import json
import random
import hashlib
import base64
from datetime import timedelta, datetime
from typing import Optional

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Depends, HTTPException, status, Request, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.responses import JSONResponse

from sqlalchemy import Column, Integer, String, Boolean, ForeignKey, DateTime, Text, Index, create_engine, inspect, exc
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship, sessionmaker, Session
from sqlalchemy.sql import func

from passlib.context import CryptContext
from cryptography.fernet import Fernet
from jose import JWTError, jwt
import uvicorn
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ============= CONFIGURATION =============
SECRET_KEY = os.getenv("SECRET_KEY", "quantum-foam-secret-2025-change-in-prod")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./holo_db.db")

# Render PostgreSQL fix
if DATABASE_URL and DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

# Fallback if empty
if not DATABASE_URL or DATABASE_URL.strip() == '':
    logger.warning("DATABASE_URL empty; falling back to SQLite for startup")
    DATABASE_URL = "sqlite:///./holo_db.db"

CLEARNET_GATE_URL = os.getenv("CLEARNET_GATE_URL", "https://clearnet-gate.onrender.com")

# ============= DATABASE SETUP =============
try:
    engine = create_engine(
        DATABASE_URL,
        connect_args={"check_same_thread": False} if "sqlite" in DATABASE_URL else {},
        pool_pre_ping=True,
        pool_size=int(os.getenv("SQLALCHEMY_POOL_SIZE", 2)),
        max_overflow=int(os.getenv("SQLALCHEMY_MAX_OVERFLOW", 3)),
        pool_timeout=60,
        pool_recycle=3600
    )
    # Test connection
    with engine.connect() as conn:
        conn.execute("SELECT 1")
    logger.info("✅ Database connection successful")
except Exception as e:
    logger.error(f"❌ Database connection failed: {e}")
    raise

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# ============= MODELS =============
pwd_context = CryptContext(schemes=["argon2"], deprecated="auto")

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(50), unique=True, index=True, nullable=False)
    domain = Column(String(50), default="quantum", nullable=False)
    hashed_password = Column(String(255), nullable=False)
    labels = Column(String(500), default="")
    email = Column(String(100), unique=True, index=True)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    contacts = relationship("Contact", back_populates="user", cascade="all, delete-orphan")
    messages_sent = relationship("Message", foreign_keys="Message.sender_id", back_populates="sender")
    messages_received = relationship("Message", foreign_keys="Message.receiver_id", back_populates="receiver")
    emails_sent = relationship("Email", foreign_keys="Email.sender_id", back_populates="sender")
    emails_received = relationship("Email", foreign_keys="Email.receiver_id", back_populates="receiver")

    def set_password(self, password: str):
        self.hashed_password = pwd_context.hash(password)

    def verify_password(self, password: str) -> bool:
        return pwd_context.verify(password, self.hashed_password)

    @property
    def full_email(self):
        return f"{self.username}@{self.domain}.foam.computer"

class Contact(Base):
    __tablename__ = "contacts"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    contact_email = Column(String(100), nullable=False)
    name = Column(String(100))
    is_starred = Column(Boolean, default=False)
    labels = Column(String(200), default="")

    user = relationship("User", back_populates="contacts")

class Message(Base):
    __tablename__ = "messages"

    id = Column(Integer, primary_key=True, index=True)
    sender_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    receiver_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    encrypted_content = Column(Text, nullable=False)
    black_hole_hash = Column(String(128), nullable=False)
    is_ai = Column(Boolean, default=False)
    timestamp = Column(DateTime(timezone=True), server_default=func.now())
    is_deleted = Column(Boolean, default=False)

    sender = relationship("User", foreign_keys=[sender_id], back_populates="messages_sent")
    receiver = relationship("User", foreign_keys=[receiver_id], back_populates="messages_received")

    __table_args__ = (
        Index('idx_sender_receiver', sender_id, receiver_id),
        Index('idx_timestamp', timestamp.desc()),
    )

    @property
    def content(self):
        if self.encrypted_content and not self.is_deleted:
            try:
                key = derive_key_from_collider(self.black_hole_hash)
                f = Fernet(key)
                return f.decrypt(self.encrypted_content.encode()).decode()
            except Exception:
                return "[Decryption failed]"
        return None

class Email(Base):
    __tablename__ = "emails"

    id = Column(Integer, primary_key=True, index=True)
    sender_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    receiver_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    subject = Column(String(200), nullable=False)
    encrypted_body = Column(Text, nullable=False)
    black_hole_hash = Column(String(128), nullable=False)
    folder = Column(String(50), default="Inbox")
    label = Column(String(200), default="")
    is_starred = Column(Boolean, default=False)
    is_deleted = Column(Boolean, default=False)
    timestamp = Column(DateTime(timezone=True), server_default=func.now())

    sender = relationship("User", foreign_keys=[sender_id], back_populates="emails_sent")
    receiver = relationship("User", foreign_keys=[receiver_id], back_populates="emails_received")

    __table_args__ = (
        Index('idx_receiver_folder', receiver_id, folder),
        Index('idx_email_timestamp', timestamp.desc()),
    )

    @property
    def body(self):
        if self.encrypted_body and not self.is_deleted:
            try:
                key = derive_key_from_collider(self.black_hole_hash)
                f = Fernet(key)
                return f.decrypt(self.encrypted_body.encode()).decode()
            except Exception:
                return "[Decryption failed]"
        return None

# ============= CRYPTO FUNCTIONS =============
def derive_key_from_collider(black_hole_hash: str) -> bytes:
    """Derive encryption key from black hole hash"""
    key_material = hashlib.pbkdf2_hmac('sha512', black_hole_hash.encode(), b'foam-salt', 100000)[:32]
    return base64.urlsafe_b64encode(key_material)

def create_black_hole_hash(content: str) -> str:
    """Generate black hole hash with white hole entropy"""
    white_hole_seed = ''.join(random.choices('abcdefghijklmnopqrstuvwxyz0123456789!@#$', k=64))
    combined = content + white_hole_seed
    return hashlib.sha3_512(combined.encode()).hexdigest()

def encrypt_with_collider(content: str) -> tuple:
    """Encrypt content with collider encryption"""
    hash_val = create_black_hole_hash(content)
    key = derive_key_from_collider(hash_val)
    f = Fernet(key)
    encrypted = f.encrypt(content.encode()).decode()
    return encrypted, hash_val

# ============= AUTH =============
security = HTTPBearer()

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security), db: Session = Depends(get_db)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(credentials.credentials, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    
    user = db.query(User).filter(User.username == username, User.is_active == True).first()
    if user is None:
        raise credentials_exception
    return user

# ============= FASTAPI APP =============
app = FastAPI(
    title="Clearnet Chat - Quantum Foam Chatroom",
    description="Secure messaging with quantum collider encryption",
    version="1.0.0"
)

# CORS configuration
allowed_origins = [
    "http://localhost:3000",
    "http://localhost:5173",
    CLEARNET_GATE_URL,
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins + ["*"],  # Allow all in production for flexibility
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ============= CONNECTION MANAGER =============
class ConnectionManager:
    def __init__(self):
        self.active_connections: dict[int, WebSocket] = {}

    async def connect(self, websocket: WebSocket, user_id: int):
        await websocket.accept()
        self.active_connections[user_id] = websocket

    def disconnect(self, user_id: int):
        self.active_connections.pop(user_id, None)

    async def send_personal(self, message: str, user_id: int):
        if user_id in self.active_connections:
            try:
                await self.active_connections[user_id].send_text(message)
            except Exception:
                self.disconnect(user_id)

    async def broadcast_to_matches(self, message: str, sender_labels: str, db: Session):
        sender_label_list = [l.strip() for l in sender_labels.split(',') if l.strip()]
        for uid, ws in list(self.active_connections.items()):
            try:
                user = db.query(User).filter(User.id == uid).first()
                if user:
                    user_labels = [l.strip() for l in user.labels.split(',') if l.strip()]
                    if any(label in user_labels for label in sender_label_list):
                        await ws.send_text(message)
            except Exception:
                self.disconnect(uid)

manager = ConnectionManager()

# ============= API ENDPOINTS =============

@app.get("/")
async def root():
    return {
        "service": "clearnet_chat",
        "status": "online",
        "message": "Quantum Foam Chatroom API",
        "gateway": CLEARNET_GATE_URL
    }

@app.get("/health")
async def health_check():
    return {"status": "healthy", "service": "clearnet_chat"}

# Registration
@app.post("/api/register")
async def register(
    request: Request,
    db: Session = Depends(get_db)
):
    try:
        data = await request.json()
        username = data.get("username", "").strip()
        password = data.get("password", "")
        domain = data.get("domain", "quantum").strip()
        labels = data.get("labels", "").strip()

        if not username or not password:
            raise HTTPException(status_code=400, detail="Username and password required")

        if db.query(User).filter(User.username == username).first():
            raise HTTPException(status_code=400, detail="Username already taken")

        user = User(username=username, domain=domain, labels=labels)
        user.set_password(password)
        user.email = user.full_email
        
        db.add(user)
        db.commit()
        db.refresh(user)

        token = create_access_token(data={"sub": username}, expires_delta=timedelta(days=7))
        
        return {
            "token": token,
            "email": user.email,
            "message": "Welcome to Foam Computer! Your messages are secured via quantum colliders."
        }
    except HTTPException:
        raise
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=str(e))

# Login
@app.post("/api/login")
async def login(
    request: Request,
    db: Session = Depends(get_db)
):
    try:
        data = await request.json()
        username = data.get("username", "").strip()
        password = data.get("password", "")
        remember_me = data.get("remember_me", False)

        user = db.query(User).filter(User.username == username).first()
        if not user or not user.verify_password(password):
            raise HTTPException(status_code=401, detail="Invalid credentials")

        if not user.is_active:
            raise HTTPException(status_code=403, detail="Account disabled")

        expires = timedelta(days=7) if remember_me else timedelta(minutes=30)
        token = create_access_token(data={"sub": username}, expires_delta=expires)

        return {
            "token": token,
            "email": user.email,
            "username": user.username,
            "message": "Login successful"
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# Forgot Password
@app.post("/api/forget-password")
async def forget_password(request: Request, db: Session = Depends(get_db)):
    try:
        data = await request.json()
        username = data.get("username", "").strip()

        user = db.query(User).filter(User.username == username).first()
        if not user:
            raise HTTPException(status_code=404, detail="User not found")

        new_pass = ''.join(random.choices('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$', k=16))
        user.set_password(new_pass)
        db.commit()

        return {
            "new_password": new_pass,
            "message": "Password reset. Change it immediately in settings."
        }
    except HTTPException:
        raise
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=str(e))

# WebSocket Chat (Fixed: Token via query param)
@app.websocket("/ws/chat")
async def chat_websocket(websocket: WebSocket, token: str = Query(...)):
    db = SessionLocal()
    user = None
    try:
        # Validate token
        try:
            payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
            username = payload.get("sub")
            user = db.query(User).filter(User.username == username, User.is_active == True).first()
            if not user:
                await websocket.close(code=1008)
                return
        except JWTError:
            await websocket.close(code=1008)
            return

        await manager.connect(websocket, user.id)

        while True:
            data = await websocket.receive_text()
            parsed = json.loads(data)
            content = parsed.get("content", "")
            receiver_id = parsed.get("receiver_id")

            if not content:
                continue

            # Encrypt message
            encrypted, bhash = encrypt_with_collider(content)
            message = Message(
                sender_id=user.id,
                receiver_id=receiver_id,
                encrypted_content=encrypted,
                black_hole_hash=bhash
            )
            db.add(message)
            db.commit()

            # AI response
            if "/ai" in content.lower() or any("ai" in label.lower() for label in user.labels.split(',') if label.strip()):
                ai_resp = f"Grok Clone: Resonating with your query through foam... {content.upper()}"
                await manager.send_personal(
                    json.dumps({"content": ai_resp, "is_ai": True, "sender": "AI"}),
                    user.id
                )

            # Send to receiver or broadcast
            response_data = {
                "content": content,
                "sender": user.username,
                "sender_id": user.id,
                "timestamp": datetime.utcnow().isoformat()
            }
            
            if receiver_id:
                await manager.send_personal(json.dumps(response_data), int(receiver_id))
            else:
                await manager.broadcast_to_matches(json.dumps(response_data), user.labels, db)

    except WebSocketDisconnect:
        if user:
            manager.disconnect(user.id)
    except Exception as e:
        logger.error(f"WebSocket error: {e}")
        if user:
            manager.disconnect(user.id)
    finally:
        db.close()

# Inbox - Get emails
@app.get("/api/inbox")
async def get_inbox(
    search: str = "",
    folder: str = "Inbox",
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    try:
        query = db.query(Email).filter(
            Email.receiver_id == current_user.id,
            Email.folder == folder,
            Email.is_deleted == False
        )

        if search:
            query = query.filter(
                (Email.subject.like(f"%{search}%")) | 
                (Email.encrypted_body.like(f"%{search}%"))
            )

        emails = query.order_by(Email.timestamp.desc()).limit(100).all()

        return [{
            "id": e.id,
            "subject": e.subject,
            "body": e.body[:200] if e.body else "",
            "folder": e.folder,
            "label": e.label,
            "is_starred": e.is_starred,
            "timestamp": e.timestamp.isoformat(),
            "sender_id": e.sender_id
        } for e in emails]
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# Inbox - Send email
@app.post("/api/inbox/send")
async def send_email(
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    try:
        data = await request.json()
        receiver_email = data.get("receiver_email", "").strip()
        subject = data.get("subject", "").strip()
        body = data.get("body", "")

        if not receiver_email or not subject:
            raise HTTPException(status_code=400, detail="Receiver and subject required")

        receiver = db.query(User).filter(User.email == receiver_email).first()
        if not receiver:
            raise HTTPException(status_code=404, detail="Receiver not found")

        encrypted, bhash = encrypt_with_collider(body)
        email = Email(
            sender_id=current_user.id,
            receiver_id=receiver.id,
            subject=subject,
            encrypted_body=encrypted,
            black_hole_hash=bhash
        )
        db.add(email)
        db.commit()

        return {"message": "Email sent successfully"}
    except HTTPException:
        raise
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=str(e))

# Delete email
@app.delete("/api/inbox/{email_id}")
async def delete_email(
    email_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    try:
        email = db.query(Email).filter(
            Email.id == email_id,
            Email.receiver_id == current_user.id
        ).first()
        
        if not email:
            raise HTTPException(status_code=404, detail="Email not found")

        email.is_deleted = True
        db.commit()

        return {"message": "Email deleted"}
    except HTTPException:
        raise
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=str(e))

# Contacts - Add
@app.post("/api/contacts")
async def add_contact(
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    try:
        data = await request.json()
        contact_email = data.get("contact_email", "").strip()
        name = data.get("name", "").strip()

        if not contact_email:
            raise HTTPException(status_code=400, detail="Contact email required")

        contact = Contact(
            user_id=current_user.id,
            contact_email=contact_email,
            name=name
        )
        db.add(contact)
        db.commit()

        return {"message": "Contact added"}
    except HTTPException:
        raise
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=str(e))

# Contacts - Import
@app.post("/api/contacts/import")
async def import_contacts(
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    try:
        data = await request.json()
        contacts_data = data.get("data", "")

        lines = contacts_data.strip().split('\n')
        imported = 0

        for line in lines:
            if ',' in line:
                parts = line.split(',', 1)
                email = parts[0].strip()
                name = parts[1].strip() if len(parts) > 1 else ""
                
                if email:
                    contact = Contact(
                        user_id=current_user.id,
                        contact_email=email,
                        name=name
                    )
                    db.add(contact)
                    imported += 1

        db.commit()
        return {"message": f"Imported {imported} contacts"}
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=str(e))

# Get contacts
@app.get("/api/contacts")
async def get_contacts(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    try:
        contacts = db.query(Contact).filter(Contact.user_id == current_user.id).all()
        return [{
            "id": c.id,
            "contact_email": c.contact_email,
            "name": c.name,
            "is_starred": c.is_starred,
            "labels": c.labels
        } for c in contacts]
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# Global exception handler
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    logger.error(f"Error: {exc}", exc_info=True)
    return JSONResponse(
        status_code=500,
        content={
            "error": "Internal server error",
            "timestamp": datetime.now().isoformat()
        }
    )

# ============= STARTUP =============
@app.on_event("startup")
async def startup_event():
    try:
        # Test DB again
        with engine.connect() as conn:
            conn.execute("SELECT 1")
        
        # Check if tables already exist
        inspector = inspect(engine)
        if not inspector.has_table("users", schema=inspector.default_schema_name):
            Base.metadata.create_all(bind=engine)
            logger.info("✅ Database tables created")
        else:
            logger.info("✅ Database tables already exist")
        
        db_type = "PostgreSQL" if "postgresql" in DATABASE_URL else "SQLite"
        logger.info(f"✅ Clearnet Chat running on {db_type}")
    except Exception as e:
        logger.error(f"❌ Startup failed: {e}")
        # Don't raise, let app start anyway - tables can be created on first request if needed
        logger.info("🚀 App starting despite startup error")

if __name__ == "__main__":
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=port,
        log_level="info",
        access_log=True
    )
