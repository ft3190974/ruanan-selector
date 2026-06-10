"""选型助手后端 - 用户管理 + 线索记录"""
import hashlib, secrets, os, json, time, re
from datetime import datetime, timedelta
from pathlib import Path
import aiosqlite
from fastapi import FastAPI, Form, HTTPException, Request, UploadFile, File
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware

BASE_DIR = Path(__file__).parent
DB_PATH = BASE_DIR / "selector.db"
STATIC_FILE = Path(r"C:\Users\常乐\Desktop\软安科技\ruanan-product-selector.html")
ADMIN_PWD = os.environ.get("ADMIN_PWD", secrets.token_hex(16))  # 环境变量或随机生成

# ── 安全配置 ──
MIN_PASSWORD_LENGTH = 8
TOKEN_EXPIRE_HOURS = 24
LOGIN_MAX_ATTEMPTS = 10
LOGIN_WINDOW_SECONDS = 300  # 5分钟内最多10次尝试

# 简单的内存限速存储 (生产环境应使用 Redis)
_login_attempts: dict[str, list[float]] = {}

def check_login_rate(ip: str) -> bool:
    """检查IP是否超过登录频率限制"""
    now = time.time()
    attempts = _login_attempts.get(ip, [])
    # 清理过期记录
    attempts = [t for t in attempts if now - t < LOGIN_WINDOW_SECONDS]
    _login_attempts[ip] = attempts
    return len(attempts) < LOGIN_MAX_ATTEMPTS

def record_login_attempt(ip: str):
    """记录一次登录尝试"""
    now = time.time()
    if ip not in _login_attempts:
        _login_attempts[ip] = []
    _login_attempts[ip].append(now)
    # 清理过期
    _login_attempts[ip] = [t for t in _login_attempts[ip] if now - t < LOGIN_WINDOW_SECONDS]

def validate_password_strength(password: str) -> str | None:
    """验证密码强度，返回错误信息或None"""
    if len(password) < MIN_PASSWORD_LENGTH:
        return f"密码至少需要{MIN_PASSWORD_LENGTH}位字符"
    if not re.search(r'[A-Za-z]', password):
        return "密码需包含至少一个字母"
    if not re.search(r'[0-9]', password):
        return "密码需包含至少一个数字"
    return None

def validate_username(username: str) -> str | None:
    """验证用户名格式"""
    if not re.match(r'^[a-zA-Z0-9_一-鿿]{4,20}$', username):
        return "用户名需4-20位字母、数字、下划线或中文"
    return None

async def check_admin_auth(request: Request, db) -> dict | None:
    """验证管理员权限，返回用户行或None"""
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    if not token:
        return None
    row = await db_fetchone(db,
        "SELECT u.* FROM users u JOIN api_tokens t ON u.id=t.user_id "
        "WHERE t.token=? AND u.role='admin' AND t.created_at > datetime('now','localtime','-" + str(TOKEN_EXPIRE_HOURS) + " hours')",
        (token,))
    return row

async def require_admin(request: Request):
    """要求管理员权限，否则抛403"""
    db = await get_db()
    try:
        admin = await check_admin_auth(request, db)
        if not admin:
            raise HTTPException(403, "需要管理员权限或token已过期")
        return admin
    finally:
        await db.close()

def safe_str(val: str, max_len: int = 500) -> str:
    """安全截断字符串"""
    if not val:
        return ""
    return val[:max_len].strip()

# ── 验证码: 100以内加减乘除 ──
import random as _random
_captcha_store: dict[str, tuple[int, float]] = {}  # captcha_id -> (answer, timestamp)
CAPTCHA_EXPIRE_SECONDS = 120  # 验证码2分钟过期
CAPTCHA_CLEANUP_INTERVAL = 300  # 每5分钟清理一次
_last_captcha_cleanup = time.time()

def _cleanup_captcha():
    """清理过期验证码"""
    global _last_captcha_cleanup
    now = time.time()
    if now - _last_captcha_cleanup < CAPTCHA_CLEANUP_INTERVAL:
        return
    _last_captcha_cleanup = now
    expired = [k for k, v in _captcha_store.items() if now - v[1] > CAPTCHA_EXPIRE_SECONDS]
    for k in expired:
        del _captcha_store[k]

def generate_captcha() -> tuple[str, str, int]:
    """生成验证码，返回 (captcha_id, question_text, answer)"""
    _cleanup_captcha()
    a = _random.randint(1, 99)
    b = _random.randint(1, 99)
    op = _random.choice(['+', '-', '*'])
    if op == '+':
        answer = a + b
        question = f"{a} + {b} = ?"
    elif op == '-':
        # 确保结果非负
        if a < b: a, b = b, a
        answer = a - b
        question = f"{a} - {b} = ?"
    else:  # '*'
        # 乘法控制在简单范围：1-9 或 10-20 × 1-5
        if a > 20: a = _random.randint(1, 9)
        if b > 20: b = _random.randint(1, 9)
        answer = a * b
        question = f"{a} × {b} = ?"
    captcha_id = secrets.token_hex(16)
    _captcha_store[captcha_id] = (answer, time.time())
    return captcha_id, question, answer

def verify_captcha(captcha_id: str, user_answer: str) -> bool:
    """验证验证码答案"""
    if not captcha_id or captcha_id not in _captcha_store:
        return False
    expected, ts = _captcha_store[captcha_id]
    if time.time() - ts > CAPTCHA_EXPIRE_SECONDS:
        del _captcha_store[captcha_id]
        return False
    # 使用后立即删除，防止重放
    del _captcha_store[captcha_id]
    try:
        return int(user_answer.strip()) == expected
    except (ValueError, TypeError):
        return False

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
    # Create default admin if not exists
    try:
        ph = hashlib.sha256(ADMIN_PWD.encode()).hexdigest()
        existing = await db_fetchone(db, "SELECT id FROM users WHERE username='admin'")
        if not existing:
            await db.execute("INSERT INTO users(username,password_hash,role,email) VALUES(?,?,'admin','admin@ruanan.com')", ('admin', ph))
        else:
            # Update admin password to current ADMIN_PWD
            await db.execute("UPDATE users SET password_hash=? WHERE username='admin'", (ph,))
    except: pass
    # Clean expired tokens
    try:
        expire_time = (datetime.now() - timedelta(hours=TOKEN_EXPIRE_HOURS)).strftime('%Y-%m-%d %H:%M:%S')
        await db.execute("DELETE FROM api_tokens WHERE created_at < ?", (expire_time,))
    except: pass
    await db.commit()
    await db.close()

# ── Auth ──
@app.post("/api/register")
async def register(username: str = Form(...), password: str = Form(...), email: str = Form(""), phone: str = Form(""), company: str = Form("")):
    # 输入验证
    uname_err = validate_username(username)
    if uname_err: raise HTTPException(400, uname_err)
    pwd_err = validate_password_strength(password)
    if pwd_err: raise HTTPException(400, pwd_err)
    email = safe_str(email, 200)
    phone = safe_str(phone, 30)
    company = safe_str(company, 200)

    db = await get_db()
    try:
        existing = await db_fetchone(db, "SELECT id FROM users WHERE username=?", (username,))
        if existing: raise HTTPException(400, "用户名已存在")
        ph = hashlib.sha256(password.encode()).hexdigest()
        cur = await db.execute("INSERT INTO users(username,password_hash,email,phone,company) VALUES(?,?,?,?,?)", (username, ph, email, phone, company))
        await db.commit(); uid = cur.lastrowid
        token = secrets.token_hex(32)
        await db.execute("INSERT INTO api_tokens(user_id,token) VALUES(?,?)", (uid, token))
        await db.commit()
        return {"token": token, "username": username, "role": "user"}
    except HTTPException: raise
    except Exception as e:
        if "UNIQUE" in str(e) or "unique" in str(e):
            raise HTTPException(400, "用户名已存在")
        raise HTTPException(500, "注册失败，请稍后重试")
    finally:
        await db.close()

@app.get("/api/captcha")
async def get_captcha():
    """获取算术验证码"""
    captcha_id, question, _ = generate_captcha()
    return {"captcha_id": captcha_id, "question": question}

@app.post("/api/login")
async def login(request: Request, username: str = Form(...), password: str = Form(...),
                captcha_id: str = Form(""), captcha_answer: str = Form("")):
    client_ip = request.client.host if request.client else "unknown"

    # 验证码检查
    if not verify_captcha(captcha_id, captcha_answer):
        raise HTTPException(400, "验证码错误或已过期，请刷新重试")

    # 频率限制
    if not check_login_rate(client_ip):
        raise HTTPException(429, "登录尝试过于频繁，请5分钟后再试")
    record_login_attempt(client_ip)

    username = safe_str(username, 50)
    if not username or not password:
        raise HTTPException(400, "用户名和密码不能为空")

    db = await get_db()
    try:
        ph = hashlib.sha256(password.encode()).hexdigest()
        row = await db_fetchone(db,
            "SELECT * FROM users WHERE username=? AND password_hash=?", (username, ph))
        if not row: raise HTTPException(401, "用户名或密码错误")
        token = secrets.token_hex(32)
        await db.execute("INSERT INTO api_tokens(user_id,token) VALUES(?,?)", (row["id"], token))
        await db.commit()
        return {"token": token, "username": row["username"], "role": row["role"],
                "email": row["email"], "phone": row["phone"], "company": row["company"]}
    except HTTPException: raise
    finally:
        await db.close()

@app.post("/api/forgot-password")
async def forgot_password(username: str = Form(...), email: str = Form(...)):
    username = safe_str(username, 50)
    email = safe_str(email, 200)
    if not username or not email:
        raise HTTPException(400, "用户名和邮箱不能为空")
    db = await get_db()
    try:
        row = await db_fetchone(db, "SELECT * FROM users WHERE username=? AND email=?", (username, email))
        if not row: raise HTTPException(404, "未找到匹配的用户名和邮箱")
        new_pwd = secrets.token_hex(10)  # 20位随机密码
        ph = hashlib.sha256(new_pwd.encode()).hexdigest()
        await db.execute("UPDATE users SET password_hash=? WHERE id=?", (ph, row["id"]))
        await db.commit()
        # 不直接返回明文密码，而是提示用户
        return {"message": "密码已重置，新密码为: " + new_pwd + "。请使用新密码登录后立即修改密码。"}
    except HTTPException: raise
    finally:
        await db.close()

@app.get("/api/me")
async def me(request: Request):
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    if not token: return {"username": "guest", "role": "guest"}
    db = await get_db()
    try:
        row = await db_fetchone(db,
            "SELECT u.* FROM users u JOIN api_tokens t ON u.id=t.user_id "
            "WHERE t.token=? AND t.created_at > datetime('now','localtime','-" + str(TOKEN_EXPIRE_HOURS) + " hours')",
            (token,))
        if not row: return {"username": "guest", "role": "guest"}
        return {"username": row["username"], "role": row["role"], "email": row["email"], "phone": row["phone"], "company": row["company"]}
    finally:
        await db.close()

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
    db = await get_db()
    try:
        admin = await check_admin_auth(request, db)
        if not admin:
            raise HTTPException(403, "需要管理员权限")
        users = await db_fetchall(db, "SELECT id, username, email, phone, company, role, created_at FROM users ORDER BY created_at DESC")
        return [dict(u) for u in users]
    except HTTPException: raise
    finally:
        await db.close()

@app.post("/api/admin/users")
async def admin_create_user(request: Request, username: str = Form(...), password: str = Form(...), email: str = Form(""), phone: str = Form(""), company: str = Form(""), role: str = Form("user")):
    uname_err = validate_username(username)
    if uname_err: raise HTTPException(400, uname_err)
    pwd_err = validate_password_strength(password)
    if pwd_err: raise HTTPException(400, pwd_err)
    role = safe_str(role, 20)
    if role not in ('user', 'admin'): role = 'user'

    db = await get_db()
    try:
        admin = await check_admin_auth(request, db)
        if not admin: raise HTTPException(403, "需要管理员权限")
        ph = hashlib.sha256(password.encode()).hexdigest()
        cur = await db.execute("INSERT INTO users(username,password_hash,email,phone,company,role) VALUES(?,?,?,?,?,?)", (username, ph, email, phone, company, role))
        await db.commit(); uid = cur.lastrowid
        return {"id": uid}
    except HTTPException: raise
    except Exception as e:
        if "UNIQUE" in str(e) or "unique" in str(e):
            raise HTTPException(400, "用户名已存在")
        raise HTTPException(500, "创建用户失败")
    finally:
        await db.close()

@app.put("/api/admin/users/{uid}/reset-password")
async def admin_reset_password(uid: int, request: Request, new_password: str = Form(...)):
    pwd_err = validate_password_strength(new_password)
    if pwd_err: raise HTTPException(400, pwd_err)
    db = await get_db()
    try:
        admin = await check_admin_auth(request, db)
        if not admin: raise HTTPException(403, "需要管理员权限")
        if uid == admin["id"]:
            raise HTTPException(400, "不能重置自己的密码，请使用修改密码功能")
        ph = hashlib.sha256(new_password.encode()).hexdigest()
        await db.execute("UPDATE users SET password_hash=? WHERE id=? AND username!='admin'", (ph, uid))
        await db.commit()
        return {"ok": True}
    except HTTPException: raise
    finally:
        await db.close()

@app.put("/api/admin/users/{uid}")
async def admin_update_user(uid: int, request: Request, username: str = Form(""), email: str = Form(""), phone: str = Form(""), company: str = Form(""), role: str = Form("")):
    db = await get_db()
    try:
        admin = await check_admin_auth(request, db)
        if not admin: raise HTTPException(403, "需要管理员权限")
        if username:
            uname_err = validate_username(username)
            if uname_err: raise HTTPException(400, uname_err)
            await db.execute("UPDATE users SET username=? WHERE id=?", (safe_str(username, 50), uid))
        if email: await db.execute("UPDATE users SET email=? WHERE id=?", (safe_str(email, 200), uid))
        if phone: await db.execute("UPDATE users SET phone=? WHERE id=?", (safe_str(phone, 30), uid))
        if company: await db.execute("UPDATE users SET company=? WHERE id=?", (safe_str(company, 200), uid))
        if role:
            r = safe_str(role, 20)
            if r in ('user', 'admin'): await db.execute("UPDATE users SET role=? WHERE id=?", (r, uid))
        await db.commit()
        return {"ok": True}
    except HTTPException: raise
    finally:
        await db.close()

@app.delete("/api/admin/users/{uid}")
async def admin_delete_user(uid: int, request: Request):
    db = await get_db()
    try:
        admin = await check_admin_auth(request, db)
        if not admin: raise HTTPException(403, "需要管理员权限")
        if uid == admin["id"]:
            raise HTTPException(400, "不能删除自己")
        await db.execute("DELETE FROM users WHERE id=? AND username!='admin'", (uid,))
        await db.commit()
        return {"ok": True}
    except HTTPException: raise
    finally:
        await db.close()

@app.get("/")
async def index(): return FileResponse(str(STATIC_FILE))

@app.on_event("startup")
async def startup():
    await init_db()
    print("=" * 60)
    print("  Ruanan Tech - Smart Product Selector API v2.1")
    print("  Address: http://localhost:8081")
    if not os.environ.get("ADMIN_PWD"):
        print(f"  Admin account: admin")
        print(f"  Admin password: {ADMIN_PWD}")
        print("  [!] Save this password! Set ADMIN_PWD env var to override.")
    print("=" * 60)

if __name__ == "__main__":
    import uvicorn; uvicorn.run(app, host="0.0.0.0", port=8081, log_level="info")
