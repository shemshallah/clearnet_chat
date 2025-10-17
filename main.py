import os
from pathlib import Path
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import RedirectResponse, JSONResponse, FileResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.middleware.cors import CORSMiddleware
import uvicorn
import logging
from datetime import datetime
import httpx

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Configuration
STATIC_DIR = Path("static")
TEMPLATES_DIR = Path("templates")
STATIC_DIR.mkdir(exist_ok=True)
TEMPLATES_DIR.mkdir(exist_ok=True)

# Env var for backend URLs
CHAT_BACKEND = os.getenv("CHAT_BACKEND_URL", "https://clearnet-chat-4bal.onrender.com")

# Create FastAPI app
app = FastAPI(
    title="Clearnet Gate - Quantum Foam Gateway",
    description="Frontend proxy and static server for Quantum Foam Network",
    version="2.0.0"
)

# Templates
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount static files (for CSS/JS/images if added)
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

# In-memory simple storage if needed (e.g., for temp files)
temp_storage = {}

# Helper: Proxy requests to chat backend
async def proxy_to_chat(request: Request, path: str):
    """Proxy API/WS requests to chat backend"""
    backend_url = f"{CHAT_BACKEND}/{path}"
    
    # Handle query params
    params = dict(request.query_params)
    
    # Handle body for POST/PUT etc.
    body = None
    if request.method in ["POST", "PUT", "PATCH"]:
        body = await request.body()
    
    async with httpx.AsyncClient(timeout=httpx.Timeout(30.0)) as client:
        resp = await client.request(
            method=request.method,
            url=backend_url,
            params=params,
            content=body,
            headers={
                k: v for k, v in request.headers.items()
                if k.lower() not in ["host", "content-length"]
            }
        )
        return JSONResponse(
            content=resp.content,
            status_code=resp.status_code,
            headers=dict(resp.headers)
        )

# Routes
@app.get("/")
async def root():
    """Serve main chat HTML page"""
    # Read the HTML file or inline it
    html_content = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Clearnet Chat - Quantum Foam Chatroom</title>
    <style>
        body { font-family: Arial, sans-serif; background: linear-gradient(135deg, #0f0f23, #1a1a2e); color: #e0e0e0; margin: 0; padding: 20px; }
        .container { max-width: 800px; margin: 0 auto; background: rgba(0,0,0,0.8); border-radius: 10px; padding: 20px; box-shadow: 0 0 20px rgba(0,255,255,0.1); }
        h1 { text-align: center; color: #00ffff; text-shadow: 0 0 10px #00ffff; }
        form { display: flex; flex-direction: column; gap: 10px; margin-bottom: 20px; }
        input, button { padding: 10px; border: 1px solid #00ffff; border-radius: 5px; background: transparent; color: #e0e0e0; }
        button { cursor: pointer; background: #00ffff; color: #000; font-weight: bold; }
        button:hover { box-shadow: 0 0 10px #00ffff; }
        .chat-container { border: 1px solid #00ffff; height: 400px; overflow-y: scroll; padding: 10px; background: rgba(0,0,0,0.5); border-radius: 5px; margin-bottom: 10px; }
        .message { margin-bottom: 10px; padding: 5px; border-radius: 5px; }
        .message.sent { background: rgba(0,255,255,0.1); text-align: right; }
        .message.received { background: rgba(255,0,255,0.1); }
        .message.ai { background: rgba(255,165,0,0.2); font-style: italic; }
        #messageInput { width: 70%; }
        #sendButton { width: 25%; }
        .hidden { display: none; }
        .error { color: #ff0000; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🌊 Quantum Foam Chatroom</h1>
        
        <!-- Login/Register Form -->
        <div id="authForm">
            <h2 id="formTitle">Login</h2>
            <form id="authFormElement">
                <input type="text" id="username" placeholder="Username" required>
                <input type="password" id="password" placeholder="Password" required>
                <input type="email" id="email" placeholder="Email (for register)" style="display: none;">
                <label><input type="checkbox" id="rememberMe"> Remember Me</label>
                <button type="submit" id="submitBtn">Login</button>
                <button type="button" id="toggleForm">Register Instead</button>
            </form>
            <p id="errorMsg" class="error hidden"></p>
        </div>

        <!-- Chat Interface -->
        <div id="chatInterface" class="hidden">
            <div class="chat-container" id="messages"></div>
            <input type="text" id="messageInput" placeholder="Type a message...">
            <button id="sendButton">Send</button>
            <button id="logoutBtn">Logout</button>
        </div>
    </div>

    <script>
        const API_BASE = '/api';  // Proxied to backend
        const WS_URL = 'wss://clearnet-chat-4bal.onrender.com/ws/chat';  // Direct to backend for WS
        let ws = null;
        let token = localStorage.getItem('token') || null;
        let currentUser = null;

        // Toggle between login and register
        document.getElementById('toggleForm').onclick = () => {
            const formTitle = document.getElementById('formTitle');
            const emailInput = document.getElementById('email');
            const submitBtn = document.getElementById('submitBtn');
            if (formTitle.textContent === 'Login') {
                formTitle.textContent = 'Register';
                emailInput.style.display = 'block';
                submitBtn.textContent = 'Register';
            } else {
                formTitle.textContent = 'Login';
                emailInput.style.display = 'none';
                submitBtn.textContent = 'Login';
            }
        };

        // Handle auth submit
        document.getElementById('authFormElement').onsubmit = async (e) => {
            e.preventDefault();
            const isRegister = document.getElementById('formTitle').textContent === 'Register';
            const username = document.getElementById('username').value;
            const password = document.getElementById('password').value;
            const email = document.getElementById('email').value;
            const rememberMe = document.getElementById('rememberMe').checked;

            const endpoint = isRegister ? '/register' : '/login';
            const body = isRegister ? { username, password, email } : { username, password, remember_me: rememberMe };

            try {
                const res = await fetch(`${API_BASE}${endpoint}`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(body)
                });
                const data = await res.json();
                if (res.ok) {
                    token = data.token;
                    currentUser = { username: data.username || username, email: data.email };
                    if (rememberMe) localStorage.setItem('token', token);
                    showChat();
                } else {
                    showError(data.message || 'Authentication failed');
                }
            } catch (err) {
                showError('Network error: ' + err.message);
            }
        };

        function showError(msg) {
            const errorEl = document.getElementById('errorMsg');
            errorEl.textContent = msg;
            errorEl.classList.remove('hidden');
        }

        function showChat() {
            document.getElementById('authForm').classList.add('hidden');
            document.getElementById('chatInterface').classList.remove('hidden');
            connectWebSocket();
        }

        function connectWebSocket() {
            if (!token) return;
            ws = new WebSocket(`${WS_URL}?token=${token}`);
            ws.onopen = () => console.log('Connected to chat');
            ws.onmessage = (event) => {
                const msg = JSON.parse(event.data);
                addMessage(msg);
            };
            ws.onclose = () => setTimeout(connectWebSocket, 3000);  // Reconnect
            ws.onerror = (err) => console.error('WS error:', err);
        }

        function addMessage(msg) {
            const messagesEl = document.getElementById('messages');
            const div = document.createElement('div');
            div.className = `message ${msg.sender_id === currentUser.id ? 'sent' : msg.is_ai ? 'ai' : 'received'}`;
            div.innerHTML = `<strong>${msg.sender || 'AI'}:</strong> ${msg.content || msg.body} <small>${msg.timestamp}</small>`;
            messagesEl.appendChild(div);
            messagesEl.scrollTop = messagesEl.scrollHeight;
        }

        // Send message
        document.getElementById('sendButton').onclick = () => sendMessage();
        document.getElementById('messageInput').onkeypress = (e) => { if (e.key === 'Enter') sendMessage(); };

        function sendMessage() {
            const input = document.getElementById('messageInput');
            const content = input.value.trim();
            if (!content || !ws) return;
            ws.send(JSON.stringify({ content }));
            input.value = '';
        }

        // Logout
        document.getElementById('logoutBtn').onclick = () => {
            localStorage.removeItem('token');
            token = null;
            ws?.close();
            document.getElementById('chatInterface').classList.add('hidden');
            document.getElementById('authForm').classList.remove('hidden');
            document.getElementById('messages').innerHTML = '';
        };

        // Auto-login if token exists
        if (token) {
            showChat();
        }
    </script>
</body>
</html>
    """
    return HTMLResponse(content=html_content)

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "version": "2.0.0",
        "backend": CHAT_BACKEND
    }

# Proxy API routes to chat backend
@app.api_route("/api/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH"])
async def proxy_api(path: str, request: Request):
    """Proxy all API calls to chat backend"""
    try:
        return await proxy_to_chat(request, f"api/{path}")
    except Exception as e:
        logger.error(f"Proxy error: {e}")
        raise HTTPException(status_code=502, detail="Backend unavailable")

# Fallback for other routes (e.g., /ws/* - redirect to backend for now)
@app.get("/{path:path}")
async def catch_all(path: str):
    """Catch-all redirect or proxy"""
    if path.startswith("ws/"):
        # Redirect WS to backend
        backend_ws = f"wss://{CHAT_BACKEND.replace('https://', '')}/{path}"
        raise HTTPException(status_code=307, detail=f"WebSocket redirect to {backend_ws}")
    # Else, serve index or static
    file_path = STATIC_DIR / path
    if file_path.exists():
        return FileResponse(file_path)
    return RedirectResponse(url="/", status_code=302)

@app.on_event("startup")
async def startup_event():
    """Initialize app state"""
    logger.info(f"🚀 Gate started, proxying to {CHAT_BACKEND}")

if __name__ == "__main__":
    port = int(os.getenv("PORT", 8000))
    uvicorn.run("main:app", host="0.0.0.0", port=port, log_level="info")
