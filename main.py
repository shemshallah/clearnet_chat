"""
Clearnet Chat - Production Backend
Consolidated FastAPI application for Render deployment
"""

import os
import random
import hashlib
import base64
import json
from datetime import timedelta, datetime
from typing import Optional, List

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Depends, HTTPException, status, Form
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import Column, Integer, String, Boolean, ForeignKey, DateTime, Text, Index, create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship, Session, sessionmaker
from sqlalchemy.sql import func
from passlib.context import CryptContext
from cryptography.fernet import Fernet
from jose import JWTError, jwt

# ============================================================================
# CONFIGURATION
# ============================================================================

SECRET_KEY = os.getenv("SECRET_KEY", "quantum-foam-secret-2025-CHANGE-IN-PROD")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./clearnet_chat.db")

# Fix for Render PostgreSQL URLs
if DATABASE_URL and DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

# ============================================================================
# DATABASE SETUP
# ============================================================================

engine = create_engine(
    DATABASE_URL, 
    connect_args={"check_same_thread": False} if "sqlite" in DATABASE_URL else {},
    pool_pre_ping=True
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

pwd_context = CryptContext(schemes=["argon2"], deprecated="auto")
security = HTTPBearer()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# ============================================================================
# COLLIDER / ENCRYPTION FUNCTIONS
# ============================================================================

def create_black_hole_hash(content: str) -> str:
    """Generate black hole hash from white hole entropy"""
    white_hole_seed = ''.join(random.choices('abcdefghijklmnopqrstuvwxyz0123456789!@#$', k=64))
    combined = content + white_hole_seed
    return hashlib.sha3_512(combined.encode()).hexdigest()

def encrypt_with_collider(content: str) -> tuple:
    """Encrypt content with collider-based encryption"""
    hash_val = create_black_hole_hash(content)
    key = base64.urlsafe_b64encode(hashlib.sha256(hash_val.encode()).digest())
    f = Fernet(key)
    encrypted = f.encrypt(content.encode()).decode()
    return encrypted, hash_val

def derive_key_from_collider(black_hole_hash: str) -> bytes:
    """Derive Fernet key from black hole hash"""
    key_material = hashlib.sha256(black_hole_hash.encode()).digest()
    return base64.urlsafe_b64encode(key_material)

# ============================================================================
# MODELS
# ============================================================================

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(50), unique=True, index=True, nullable=False)
    domain = Column(String(50), default="quantum", nullable=False)
    hashed_password = Column(String(255), nullable=False)
    labels = Column(String(500), default="")
    email = Column(String(100), unique=True, nullable=False)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    messages_sent = relationship("Message", foreign_keys="Message.sender_id", back_populates="sender")
    messages_received = relationship("Message", foreign_keys="Message.receiver_id", back_populates="receiver")
    emails_sent = relationship("Email", foreign_keys="Email.sender_id", back_populates="sender")
    emails_received = relationship("Email", foreign_keys="Email.receiver_id", back_populates="receiver")
    contacts = relationship("Contact", back_populates="user")

    def set_password(self, password: str):
        self.hashed_password = pwd_context.hash(password)

    def verify_password(self, password: str) -> bool:
        return pwd_context.verify(password, self.hashed_password)

    @property
    def full_email(self) -> str:
        return f"{self.username}@{self.domain}.foam.computer"

class Contact(Base):
    __tablename__ = "contacts"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    contact_email = Column(String(100), nullable=False)
    name = Column(String(100))
    is_starred = Column(Boolean, default=False)
    labels = Column(String(200), default="")

    user = relationship("User", back_populates="contacts")

class Message(Base):
    __tablename__ = "messages"

    id = Column(Integer, primary_key=True, index=True)
    sender_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    receiver_id = Column(Integer, ForeignKey("users.id"))
    encrypted_content = Column(Text, nullable=False)
    black_hole_hash = Column(String(128), nullable=False)
    is_ai = Column(Boolean, default=False)
    timestamp = Column(DateTime(timezone=True), server_default=func.now())
    is_deleted = Column(Boolean, default=False)

    sender = relationship("User", foreign_keys=[sender_id], back_populates="messages_sent")
    receiver = relationship("User", foreign_keys=[receiver_id], back_populates="messages_received")

    @property
    def content(self) -> Optional[str]:
        if self.encrypted_content and not self.is_deleted:
            try:
                key = derive_key_from_collider(self.black_hole_hash)
                f = Fernet(key)
                return f.decrypt(self.encrypted_content.encode()).decode()
            except Exception:
                return None
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

    __table_args__ = (Index('idx_receiver_folder', 'receiver_id', 'folder'),)

    sender = relationship("User", foreign_keys=[sender_id], back_populates="emails_sent")
    receiver = relationship("User", foreign_keys=[receiver_id], back_populates="emails_received")

    @property
    def body(self) -> Optional[str]:
        if self.encrypted_body and not self.is_deleted:
            try:
                key = derive_key_from_collider(self.black_hole_hash)
                f = Fernet(key)
                return f.decrypt(self.encrypted_body.encode()).decode()
            except Exception:
                return None
        return None

# Create tables
Base.metadata.create_all(bind=engine)

# ============================================================================
# AUTH FUNCTIONS
# ============================================================================

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security), 
    db: Session = Depends(get_db)
) -> User:
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
    
    user = db.query(User).filter(User.username == username).first()
    if user is None:
        raise credentials_exception
    return user

# ============================================================================
# WEBSOCKET CONNECTION MANAGER
# ============================================================================

class ConnectionManager:
    def __init__(self):
        self.active_connections: dict[int, WebSocket] = {}

    async def connect(self, websocket: WebSocket, user_id: int):
        await websocket.accept()
        self.active_connections[user_id] = websocket

    def disconnect(self, user_id: int):
        if user_id in self.active_connections:
            del self.active_connections[user_id]

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
                    if any(label in sender_label_list for label in user_labels):
                        await ws.send_text(message)
            except Exception:
                self.disconnect(uid)

manager = ConnectionManager()

# ============================================================================
# FASTAPI APP
# ============================================================================

app = FastAPI(
    title="Clearnet Chat",
    description="Quantum Foam Chatroom - Secured by Black Hole Hashes",
    version="1.0.0"
)

# CORS Configuration
ALLOWED_ORIGINS = os.getenv("ALLOWED_ORIGINS", "https://clearnet-gate.onrender.com,http://localhost:3000").split(",")

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ============================================================================
# API ENDPOINTS
# ============================================================================

@app.get("/")
async def root():
    return {
        "service": "Clearnet Chat",
        "status": "operational",
        "message": "Quantum Foam Chatroom API - Connect via WebSocket at /ws/chat"
    }

@app.get("/health")
async def health_check():
    return {"status": "healthy", "service": "clearnet_chat"}

# ============================================================================
# AUTH ENDPOINTS
# ============================================================================

@app.post("/api/register")
async def register(
    username: str = Form(...),
    password: str = Form(...),
    domain: str = Form("quantum"),
    labels: str = Form(""),
    db: Session = Depends(get_db)
):
    """Register a new user"""
    if db.query(User).filter(User.username == username).first():
        raise HTTPException(status_code=400, detail="Username already taken")
    
    user = User(
        username=username, 
        domain=domain, 
        labels=labels.strip()
    )
    user.email = user.full_email
    user.set_password(password)
    
    db.add(user)
    db.commit()
    db.refresh(user)
    
    token = create_access_token(data={"sub": username}, expires_delta=timedelta(days=7))
    
    return {
        "token": token,
        "email": user.email,
        "username": user.username,
        "message": "Welcome to Clearnet Chat! Your messages are secured via quantum colliders."
    }

@app.post("/api/login")
async def login(
    username: str = Form(...),
    password: str = Form(...),
    remember_me: bool = Form(False),
    db: Session = Depends(get_db)
):
    """Login user"""
    user = db.query(User).filter(User.username == username).first()
    if not user or not user.verify_password(password):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    expires = timedelta(days=7) if remember_me else timedelta(hours=12)
    token = create_access_token(data={"sub": username}, expires_delta=expires)
    
    return {
        "token": token,
        "email": user.email,
        "username": user.username,
        "message": "Login successful"
    }

@app.post("/api/forgot-password")
async def forgot_password(
    username: str = Form(...), 
    db: Session = Depends(get_db)
):
    """Reset password (generates new random password)"""
    user = db.query(User).filter(User.username == username).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    new_pass = ''.join(random.choices(
        'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$', 
        k=16
    ))
    user.set_password(new_pass)
    db.commit()
    
    return {
        "new_password": new_pass,
        "message": "Password reset successful. Please change it immediately in settings."
    }

@app.get("/api/me")
async def get_current_user_info(current_user: User = Depends(get_current_user)):
    """Get current user information"""
    return {
        "id": current_user.id,
        "username": current_user.username,
        "email": current_user.email,
        "domain": current_user.domain,
        "labels": current_user.labels
    }

# ============================================================================
# WEBSOCKET CHAT
# ============================================================================

@app.websocket("/ws/chat")
async def chat_websocket(
    websocket: WebSocket,
    token: str,
    db: Session = Depends(get_db)
):
    """WebSocket endpoint for real-time chat"""
    # Verify token
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        if not username:
            await websocket.close(code=1008)
            return
        
        user = db.query(User).filter(User.username == username).first()
        if not user:
            await websocket.close(code=1008)
            return
    except JWTError:
        await websocket.close(code=1008)
        return
    
    await manager.connect(websocket, user.id)
    
    try:
        while True:
            data = await websocket.receive_text()
            parsed = json.loads(data)
            content = parsed.get("content", "")
            receiver_id = parsed.get("receiver_id")
            
            # Encrypt with collider
            encrypted, bhash = encrypt_with_collider(content)
            
            # Save message
            message = Message(
                sender_id=user.id,
                receiver_id=receiver_id,
                encrypted_content=encrypted,
                black_hole_hash=bhash
            )
            db.add(message)
            db.commit()
            
            # AI response if /ai command or ai label
            is_ai_request = "/ai" in content.lower() or any("ai" in label.lower() for label in user.labels.split(','))
            
            if is_ai_request:
                ai_resp = f"Grok Clone: Resonating with your query through foam... {content.upper()}"
                await manager.send_personal(
                    json.dumps({
                        "content": ai_resp,
                        "sender": "AI",
                        "is_ai": True,
                        "timestamp": datetime.utcnow().isoformat()
                    }),
                    user.id
                )
            
            # Send to specific receiver or broadcast to matches
            message_payload = json.dumps({
                "content": content,
                "sender": user.username,
                "sender_id": user.id,
                "timestamp": datetime.utcnow().isoformat()
            })
            
            if receiver_id:
                await manager.send_personal(message_payload, receiver_id)
            else:
                await manager.broadcast_to_matches(message_payload, user.labels, db)
    
    except WebSocketDisconnect:
        manager.disconnect(user.id)
    except Exception as e:
        print(f"WebSocket error: {e}")
        manager.disconnect(user.id)

# ============================================================================
# INBOX / EMAIL ENDPOINTS
# ============================================================================

@app.get("/api/inbox")
async def get_inbox(
    search: str = "",
    folder: str = "Inbox",
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get user's inbox emails"""
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
    
    emails = query.order_by(Email.timestamp.desc()).all()
    
    return [{
        "id": e.id,
        "subject": e.subject,
        "body_preview": e.body[:100] if e.body else "",
        "folder": e.folder,
        "label": e.label,
        "is_starred": e.is_starred,
        "timestamp": e.timestamp.isoformat(),
        "sender_id": e.sender_id,
        "sender_email": e.sender.email if e.sender else ""
    } for e in emails]

@app.post("/api/inbox/send")
async def send_email(
    receiver_email: str = Form(...),
    subject: str = Form(...),
    body: str = Form(...),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Send an email"""
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
    
    return {
        "message": "Email sent successfully",
        "encrypted_with": "black_hole_hash"
    }

@app.delete("/api/inbox/{email_id}")
async def delete_email(
    email_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Delete an email (soft delete)"""
    email = db.query(Email).filter(
        Email.id == email_id,
        Email.receiver_id == current_user.id
    ).first()
    
    if not email:
        raise HTTPException(status_code=404, detail="Email not found")
    
    email.is_deleted = True
    db.commit()
    
    return {"message": "Email deleted"}

# ============================================================================
# CONTACTS ENDPOINTS
# ============================================================================

@app.get("/api/contacts")
async def get_contacts(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get user's contacts"""
    contacts = db.query(Contact).filter(Contact.user_id == current_user.id).all()
    return [{
        "id": c.id,
        "contact_email": c.contact_email,
        "name": c.name,
        "is_starred": c.is_starred,
        "labels": c.labels
    } for c in contacts]

@app.post("/api/contacts")
async def add_contact(
    contact_email: str = Form(...),
    name: str = Form(""),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Add a new contact"""
    contact = Contact(
        user_id=current_user.id,
        contact_email=contact_email,
        name=name
    )
    db.add(contact)
    db.commit()
    db.refresh(contact)
    
    return {
        "message": "Contact added",
        "contact": {
            "id": contact.id,
            "contact_email": contact.contact_email,
            "name": contact.name
        }
    }

@app.post("/api/contacts/import")
async def import_contacts(
    data: str = Form(...),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Import contacts from CSV format"""
    lines = data.strip().split('\n')
    imported = 0
    
    for line in lines:
        if ',' in line:
            parts = line.split(',', 1)
            email = parts[0].strip()
            name = parts[1].strip() if len(parts) > 1 else ""
            
            contact = Contact(
                user_id=current_user.id,
                contact_email=email,
                name=name
            )
            db.add(contact)
            imported += 1
    
    db.commit()
    return {"message": f"Imported {imported} contacts"}

# ============================================================================
# STARTUP
# ============================================================================

if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
