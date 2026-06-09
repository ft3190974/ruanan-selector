"""选型助手后端 - 用户管理 + 线索记录"""
import hashlib, secrets, os, json
from datetime import datetime
from pathlib import Path
import aiosqlite
from fastapi import FastAPI, Form, HTTPException, Request, UploadFile, File
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware

BASE_DIR = Path(__file__).parent
DB_PATH = BASE_DIR / "selector.db"
STATIC_FILE = Path(r"C:\Users\常乐\Desktop\软安科技\ruanan-product-selector.html")
ADMIN_PWD = "ruanan2024"

app = FastAPI(title="选型助手", version="2.0.0")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

async def get_db():
    db = await aiosqlite.connect(str(DB_PATH))
    db.row_factory = aiosqlite.Row
    await db.execute("PRAGMA journal_mode=WAL")
    return db

async def db_fetchone(db, sql, params=()):
    return await (await db.execute(sql, params)).fetchone()

async def db_fetchall(db, sql, params=()):
    return await (await db.execute(sql, params)).fetchall()

async def init_db():
    db = await get_db()
    await db.executescript("""
        CREATE TABLE IF NOT EXISTS users(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            email TEXT DEFAULT '',
            phone TEXT DEFAULT '',
            company TEXT DEFAULT '',
            role TEXT DEFAULT 'user',
            created_at TEXT DEFAULT(datetime('now','localtime'))
        );
        CREATE TABLE IF NOT EXISTS leads(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            company TEXT, contact TEXT, title TEXT, email TEXT, phone TEXT, address TEXT,
            industry TEXT, scenes TEXT, budget TEXT, pains TEXT, custom_pain TEXT,
            project_budget TEXT, team_size TEXT, languages TEXT, timeline TEXT,
            type TEXT, note TEXT, submit_time TEXT DEFAULT(datetime('now','localtime'))
        );
        CREATE TABLE IF NOT EXISTS api_tokens(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER, token TEXT UNIQUE, created_at TEXT DEFAULT(datetime('now','localtime'))
        );
    """)
    # Create admin
    try:
        ph = hashlib.sha256(ADMIN_PWD.encode()).hexdigest()
        await db.execute("INSERT INTO users(username,password_hash,role,email) VALUES(?,?,'admin','admin@ruanan.com')", ('admin', ph))
    except: pass
    await db.commit()
    await db.close()

# ── Auth ──
@app.post("/api/register")
async def register(username: str = Form(...), password: str = Form(...), email: str = Form(""), phone: str = Form(""), company: str = Form("")):
    db = await get_db()
    existing = await db_fetchone(db, "SELECT id FROM users WHERE username=?", (username,))
    if existing: await db.close(); raise HTTPException(400, "用户名已存在")
    ph = hashlib.sha256(password.encode()).hexdigest()
    cur = await db.execute("INSERT INTO users(username,password_hash,email,phone,company) VALUES(?,?,?,?,?)", (username, ph, email, phone, company))
    await db.commit(); uid = cur.lastrowid; await db.close()
    token = secrets.token_hex(32)
    db2 = await get_db(); await db2.execute("INSERT INTO api_tokens(user_id,token) VALUES(?,?)", (uid, token)); await db2.commit(); await db2.close()
    return {"token": token, "username": username, "role": "user"}

@app.post("/api/login")
async def login(username: str = Form(...), password: str = Form(...)):
    db = await get_db()
    ph = hashlib.sha256(password.encode()).hexdigest()
    row = await db_fetchone(db, "SELECT * FROM users WHERE username=? AND password_hash=?", (username, ph))
    if not row: await db.close(); raise HTTPException(401, "用户名或密码错误")
    token = secrets.token_hex(32)
    await db.execute("INSERT INTO api_tokens(user_id,token) VALUES(?,?)", (row["id"], token))
    await db.commit(); await db.close()
    return {"token": token, "username": row["username"], "role": row["role"], "email": row["email"], "phone": row["phone"], "company": row["company"]}

@app.post("/api/forgot-password")
async def forgot_password(username: str = Form(...), email: str = Form(...)):
    db = await get_db()
    row = await db_fetchone(db, "SELECT * FROM users WHERE username=? AND email=?", (username, email))
    if not row: await db.close(); raise HTTPException(404, "未找到匹配的用户名和邮箱")
    new_pwd = secrets.token_hex(6)
    ph = hashlib.sha256(new_pwd.encode()).hexdigest()
    await db.execute("UPDATE users SET password_hash=? WHERE id=?", (ph, row["id"]))
    await db.commit(); await db.close()
    return {"new_password": new_pwd, "message": "密码已重置，请使用新密码登录后修改"}

@app.get("/api/me")
async def me(request: Request):
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    if not token: return {"username": "guest", "role": "guest"}
    db = await get_db()
    row = await db_fetchone(db, "SELECT u.* FROM users u JOIN api_tokens t ON u.id=t.user_id WHERE t.token=?", (token,))
    await db.close()
    if not row: return {"username": "guest", "role": "guest"}
    return {"username": row["username"], "role": row["role"], "email": row["email"], "phone": row["phone"], "company": row["company"]}

# ── Leads ──
@app.post("/api/leads")
async def save_lead(request: Request, company: str = Form(""), contact: str = Form(""), title: str = Form(""), email: str = Form(""), phone: str = Form(""), address: str = Form(""), industry: str = Form(""), scenes: str = Form(""), budget: str = Form(""), pains: str = Form(""), custom_pain: str = Form(""), project_budget: str = Form(""), team_size: str = Form(""), languages: str = Form(""), timeline: str = Form(""), type: str = Form(""), note: str = Form(""), user_id: int = Form(0)):
    db = await get_db()
    await db.execute("INSERT INTO leads(user_id,company,contact,title,email,phone,address,industry,scenes,budget,pains,custom_pain,project_budget,team_size,languages,timeline,type,note) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                     (user_id, company, contact, title, email, phone, address, industry, scenes, budget, pains, custom_pain, project_budget, team_size, languages, timeline, type, note))
    await db.commit(); await db.close()
    return {"ok": True}

@app.get("/api/leads")
async def list_leads():
    db = await get_db()
    rows = await db_fetchall(db, "SELECT l.*, u.username FROM leads l LEFT JOIN users u ON l.user_id=u.id ORDER BY l.submit_time DESC LIMIT 200")
    await db.close()
    return [dict(r) for r in rows]

# ── Admin: User Management ──
@app.get("/api/admin/users")
async def admin_list_users(request: Request):
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    db = await get_db()
    admin_row = await db_fetchone(db, "SELECT u.* FROM users u JOIN api_tokens t ON u.id=t.user_id WHERE t.token=? AND u.role='admin'", (token,))
    if not admin_row: await db.close(); raise HTTPException(403, "需要管理员权限")
    users = await db_fetchall(db, "SELECT id, username, email, phone, company, role, created_at FROM users ORDER BY created_at DESC")
    await db.close()
    return [dict(u) for u in users]

@app.post("/api/admin/users")
async def admin_create_user(request: Request, username: str = Form(...), password: str = Form(...), email: str = Form(""), phone: str = Form(""), company: str = Form(""), role: str = Form("user")):
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    db = await get_db()
    admin_row = await db_fetchone(db, "SELECT u.* FROM users u JOIN api_tokens t ON u.id=t.user_id WHERE t.token=? AND u.role='admin'", (token,))
    if not admin_row: await db.close(); raise HTTPException(403)
    ph = hashlib.sha256(password.encode()).hexdigest()
    try:
        cur = await db.execute("INSERT INTO users(username,password_hash,email,phone,company,role) VALUES(?,?,?,?,?,?)", (username, ph, email, phone, company, role))
        await db.commit(); uid = cur.lastrowid; await db.close()
        return {"id": uid}
    except: await db.close(); raise HTTPException(400, "用户名已存在")

@app.put("/api/admin/users/{uid}/reset-password")
async def admin_reset_password(uid: int, request: Request, new_password: str = Form(...)):
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    db = await get_db()
    admin_row = await db_fetchone(db, "SELECT u.* FROM users u JOIN api_tokens t ON u.id=t.user_id WHERE t.token=? AND u.role='admin'", (token,))
    if not admin_row: await db.close(); raise HTTPException(403)
    ph = hashlib.sha256(new_password.encode()).hexdigest()
    await db.execute("UPDATE users SET password_hash=? WHERE id=?", (ph, uid))
    await db.commit(); await db.close()
    return {"ok": True}

@app.put("/api/admin/users/{uid}")
async def admin_update_user(uid: int, request: Request, username: str = Form(""), email: str = Form(""), phone: str = Form(""), company: str = Form(""), role: str = Form("")):
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    db = await get_db()
    admin_row = await db_fetchone(db, "SELECT u.* FROM users u JOIN api_tokens t ON u.id=t.user_id WHERE t.token=? AND u.role='admin'", (token,))
    if not admin_row: await db.close(); raise HTTPException(403)
    if username: await db.execute("UPDATE users SET username=? WHERE id=?", (username, uid))
    if email: await db.execute("UPDATE users SET email=? WHERE id=?", (email, uid))
    if phone: await db.execute("UPDATE users SET phone=? WHERE id=?", (phone, uid))
    if company: await db.execute("UPDATE users SET company=? WHERE id=?", (company, uid))
    if role: await db.execute("UPDATE users SET role=? WHERE id=?", (role, uid))
    await db.commit(); await db.close()
    return {"ok": True}

@app.delete("/api/admin/users/{uid}")
async def admin_delete_user(uid: int, request: Request):
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    db = await get_db()
    admin_row = await db_fetchone(db, "SELECT u.* FROM users u JOIN api_tokens t ON u.id=t.user_id WHERE t.token=? AND u.role='admin'", (token,))
    if not admin_row: await db.close(); raise HTTPException(403)
    await db.execute("DELETE FROM users WHERE id=? AND username!='admin'", (uid,))
    await db.commit(); await db.close()
    return {"ok": True}

@app.get("/")
async def index(): return FileResponse(str(STATIC_FILE))

@app.on_event("startup")
async def startup():
    await init_db()
    print("Selector API v2.0: http://localhost:8081")

if __name__ == "__main__":
    import uvicorn; uvicorn.run(app, host="0.0.0.0", port=8081, log_level="info")
