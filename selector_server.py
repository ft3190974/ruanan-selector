"""软安科技华南营销管理平台 — 统一后端 API v3.0"""
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
UPLOAD_DIR = BASE_DIR / "uploads"
UPLOAD_DIR.mkdir(exist_ok=True)
STATIC_FILE = Path(r"C:\Users\常乐\Desktop\软安科技\ruanan-product-selector.html")
MARKETING_FILE = Path(r"C:\Users\常乐\Desktop\软安科技\ruanan-marketing-platform.html")
CUSTOMER_PORTAL_FILE = Path(r"C:\Users\常乐\Desktop\软安科技\ruanan-customer-portal.html")
PARTNER_FILE = Path(r"C:\Users\常乐\Desktop\软安科技\ruanan-partner-portal.html")
PROMO_VIDEO_FILE = Path(r"C:\Users\常乐\Desktop\软安科技\promo_video.html")
OUTRO_FILE = Path(r"C:\Users\常乐\Desktop\软安科技\outro.html")
ADMIN_PWD = os.environ.get("ADMIN_PWD", "admin123")

# ── 安全配置 ──
MIN_PASSWORD_LENGTH = 8
TOKEN_EXPIRE_HOURS = 24
LOGIN_MAX_ATTEMPTS = 100
LOGIN_WINDOW_SECONDS = 60

_login_attempts: dict[str, list[float]] = {}

def check_login_rate(ip: str) -> bool:
    now = time.time()
    attempts = _login_attempts.get(ip, [])
    attempts = [t for t in attempts if now - t < LOGIN_WINDOW_SECONDS]
    _login_attempts[ip] = attempts
    return len(attempts) < LOGIN_MAX_ATTEMPTS

def record_login_attempt(ip: str):
    now = time.time()
    if ip not in _login_attempts: _login_attempts[ip] = []
    _login_attempts[ip].append(now)
    _login_attempts[ip] = [t for t in _login_attempts[ip] if now - t < LOGIN_WINDOW_SECONDS]

def validate_password_strength(password: str) -> str | None:
    if len(password) < MIN_PASSWORD_LENGTH: return f"密码至少需要{MIN_PASSWORD_LENGTH}位字符"
    if not re.search(r'[A-Za-z]', password): return "密码需包含至少一个字母"
    if not re.search(r'[0-9]', password): return "密码需包含至少一个数字"
    return None

def validate_username(username: str) -> str | None:
    if not re.match(r'^[a-zA-Z0-9_一-鿿]{4,20}$', username): return "用户名需4-20位字母、数字、下划线或中文"
    return None

async def log_login(user_type, username, ip, success, detail=""):
    db = await get_db()
    try:
        await db.execute("INSERT INTO login_logs(user_type,username,ip,success,detail) VALUES(?,?,?,?,?)",(user_type,username,ip,1 if success else 0,detail))
        await db.commit()
    except: pass
    finally: await db.close()

def safe_str(val: str, max_len: int = 500) -> str:
    if not val: return ""
    return val[:max_len].strip()

# ── Auth helper: get current user from token ──
async def get_auth_user(request: Request) -> dict | None:
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    if not token: return None
    db = await get_db()
    try:
        row = await db_fetchone(db,
            "SELECT u.* FROM users u JOIN api_tokens t ON u.id=t.user_id "
            "WHERE t.token=? AND t.created_at > datetime('now','localtime','-" + str(TOKEN_EXPIRE_HOURS) + " hours')",
            (token,))
        return dict(row) if row else None
    finally:
        await db.close()

async def require_auth(request: Request) -> dict:
    user = await get_auth_user(request)
    if not user: raise HTTPException(401, "请先登录")
    return user

async def require_admin(request: Request) -> dict:
    user = await get_auth_user(request)
    if not user: raise HTTPException(401, "请先登录")
    if user["role"] != "admin": raise HTTPException(403, "需要管理员权限")
    return user

async def require_partner(request: Request) -> dict:
    user = await get_auth_user(request)
    if not user: raise HTTPException(401, "请先登录")
    if user["role"] not in ("partner", "admin"): raise HTTPException(403, "需要合作伙伴权限")
    return user

# ── Customer auth helpers ──
async def get_customer_user(request: Request) -> dict | None:
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    if not token: return None
    db = await get_db()
    try:
        row = await db_fetchone(db,
            "SELECT c.* FROM customer_users c JOIN customer_tokens t ON c.id=t.customer_id "
            "WHERE t.token=? AND t.created_at > datetime('now','localtime','-" + str(TOKEN_EXPIRE_HOURS) + " hours')",
            (token,))
        return dict(row) if row else None
    finally:
        await db.close()

async def require_customer(request: Request) -> dict:
    user = await get_customer_user(request)
    if not user: raise HTTPException(401, "请先登录客户账号")
    return user

# ── 验证码 ──
import random as _random
_captcha_store: dict[str, tuple[int, float]] = {}
CAPTCHA_EXPIRE_SECONDS = 120
_last_captcha_cleanup = time.time()

def _cleanup_captcha():
    global _last_captcha_cleanup
    now = time.time()
    if now - _last_captcha_cleanup < 300: return
    _last_captcha_cleanup = now
    expired = [k for k, v in _captcha_store.items() if now - v[1] > CAPTCHA_EXPIRE_SECONDS]
    for k in expired: del _captcha_store[k]

def generate_captcha() -> tuple[str, str, int]:
    _cleanup_captcha()
    a, b = _random.randint(1, 99), _random.randint(1, 99)
    op = _random.choice(['+', '-', '*'])
    if op == '+': answer = a + b; question = f"{a} + {b} = ?"
    elif op == '-':
        if a < b: a, b = b, a
        answer = a - b; question = f"{a} - {b} = ?"
    else:
        if a > 20: a = _random.randint(1, 9)
        if b > 20: b = _random.randint(1, 9)
        answer = a * b; question = f"{a} × {b} = ?"
    captcha_id = secrets.token_hex(16)
    _captcha_store[captcha_id] = (answer, time.time())
    return captcha_id, question, answer

def verify_captcha(captcha_id: str, user_answer: str) -> bool:
    if not captcha_id or captcha_id not in _captcha_store: return False
    expected, ts = _captcha_store[captcha_id]
    if time.time() - ts > CAPTCHA_EXPIRE_SECONDS: del _captcha_store[captcha_id]; return False
    del _captcha_store[captcha_id]
    try: return int(user_answer.strip()) == expected
    except (ValueError, TypeError): return False

app = FastAPI(title="软安华南营销平台", version="3.0.0")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])
app.mount("/uploads", StaticFiles(directory=str(UPLOAD_DIR)), name="uploads")

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
            id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL, email TEXT DEFAULT '', phone TEXT DEFAULT '',
            company TEXT DEFAULT '', role TEXT DEFAULT 'user',
            avatar_url TEXT DEFAULT '', department TEXT DEFAULT '',
            region TEXT DEFAULT '华南', created_at TEXT DEFAULT(datetime('now','localtime'))
        );
        CREATE TABLE IF NOT EXISTS leads(
            id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER,
            company TEXT, contact TEXT, title TEXT, email TEXT, phone TEXT, address TEXT,
            industry TEXT, scenes TEXT, budget TEXT, pains TEXT, custom_pain TEXT,
            project_budget TEXT, team_size TEXT, languages TEXT, timeline TEXT,
            type TEXT, note TEXT, submit_time TEXT DEFAULT(datetime('now','localtime'))
        );
        CREATE TABLE IF NOT EXISTS api_tokens(
            id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER,
            token TEXT UNIQUE, created_at TEXT DEFAULT(datetime('now','localtime'))
        );
        CREATE TABLE IF NOT EXISTS articles(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL, content TEXT DEFAULT '', summary TEXT DEFAULT '',
            category TEXT DEFAULT '行业洞察', tags TEXT DEFAULT '',
            author TEXT DEFAULT '软安科技', published INTEGER DEFAULT 1,
            created_at TEXT DEFAULT(datetime('now','localtime')),
            updated_at TEXT DEFAULT(datetime('now','localtime'))
        );
        CREATE TABLE IF NOT EXISTS cases(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL, industry TEXT DEFAULT '', tag TEXT DEFAULT '',
            description TEXT DEFAULT '', metric TEXT DEFAULT '',
            content TEXT DEFAULT '', video_url TEXT DEFAULT '', cover_url TEXT DEFAULT '',
            published INTEGER DEFAULT 1,
            created_at TEXT DEFAULT(datetime('now','localtime'))
        );
        CREATE TABLE IF NOT EXISTS partners(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER UNIQUE, company TEXT NOT NULL,
            contact TEXT DEFAULT '', phone TEXT DEFAULT '', email TEXT DEFAULT '',
            address TEXT DEFAULT '', business_scope TEXT DEFAULT '',
            status TEXT DEFAULT 'pending',
            created_at TEXT DEFAULT(datetime('now','localtime'))
        );
        CREATE TABLE IF NOT EXISTS opportunities(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            partner_id INTEGER, customer_name TEXT NOT NULL,
            industry TEXT DEFAULT '', estimated_amount TEXT DEFAULT '',
            products_interested TEXT DEFAULT '', stage TEXT DEFAULT '报备',
            notes TEXT DEFAULT '', created_at TEXT DEFAULT(datetime('now','localtime')),
            updated_at TEXT DEFAULT(datetime('now','localtime'))
        );
        CREATE TABLE IF NOT EXISTS tickets(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER, subject TEXT NOT NULL,
            description TEXT DEFAULT '', category TEXT DEFAULT '技术支持',
            status TEXT DEFAULT 'open', priority TEXT DEFAULT 'normal',
            reply TEXT DEFAULT '', replied_at TEXT DEFAULT '',
            created_at TEXT DEFAULT(datetime('now','localtime'))
        );
        CREATE TABLE IF NOT EXISTS materials(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL, description TEXT DEFAULT '',
            file_url TEXT DEFAULT '', file_type TEXT DEFAULT '',
            category TEXT DEFAULT '产品资料', download_count INTEGER DEFAULT 0,
            created_at TEXT DEFAULT(datetime('now','localtime'))
        );
        CREATE TABLE IF NOT EXISTS customer_users(
            id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL, email TEXT DEFAULT '', phone TEXT DEFAULT '',
            company TEXT DEFAULT '', contact_name TEXT DEFAULT '', position TEXT DEFAULT '',
            product_purchased TEXT DEFAULT '', industry TEXT DEFAULT '',
            valid_from TEXT DEFAULT '', valid_days INTEGER DEFAULT 365, status TEXT DEFAULT 'active',
            created_at TEXT DEFAULT(datetime('now','localtime'))
        );
        CREATE TABLE IF NOT EXISTS login_logs( id INTEGER PRIMARY KEY AUTOINCREMENT, user_type TEXT DEFAULT "internal", username TEXT, ip TEXT, success INTEGER DEFAULT 1, detail TEXT DEFAULT "", created_at TEXT DEFAULT(datetime('now','localtime')) ); CREATE TABLE IF NOT EXISTS customer_tokens(
            id INTEGER PRIMARY KEY AUTOINCREMENT, customer_id INTEGER,
            token TEXT UNIQUE, created_at TEXT DEFAULT(datetime('now','localtime'))
        );
        CREATE TABLE IF NOT EXISTS kb_articles(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL, content TEXT DEFAULT '', summary TEXT DEFAULT '',
            category TEXT DEFAULT '产品文档', tags TEXT DEFAULT '',
            product_id TEXT DEFAULT '', author TEXT DEFAULT '软安科技',
            view_count INTEGER DEFAULT 0, published INTEGER DEFAULT 1,
            created_at TEXT DEFAULT(datetime('now','localtime')),
            updated_at TEXT DEFAULT(datetime('now','localtime'))
        );
        CREATE TABLE IF NOT EXISTS qa_questions(
            id INTEGER PRIMARY KEY AUTOINCREMENT, customer_id INTEGER,
            subject TEXT NOT NULL, description TEXT DEFAULT '',
            category TEXT DEFAULT '产品使用问题', tags TEXT DEFAULT '',
            file_urls TEXT DEFAULT '', status TEXT DEFAULT 'open',
            created_at TEXT DEFAULT(datetime('now','localtime'))
        );
        CREATE TABLE IF NOT EXISTS qa_answers(
            id INTEGER PRIMARY KEY AUTOINCREMENT, question_id INTEGER NOT NULL,
            answerer_id INTEGER, content TEXT NOT NULL, is_staff INTEGER DEFAULT 0,
            created_at TEXT DEFAULT(datetime('now','localtime'))
        );
        CREATE TABLE IF NOT EXISTS product_pages(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            product_id TEXT NOT NULL UNIQUE,
            intro TEXT DEFAULT '',
            detail TEXT DEFAULT '',
            updated_at TEXT DEFAULT(datetime('now','localtime'))
        );
        CREATE TABLE IF NOT EXISTS training_modules(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            product_id TEXT NOT NULL, title TEXT NOT NULL,
            content TEXT DEFAULT '', group_name TEXT DEFAULT '产品知识',
            sort_order INTEGER DEFAULT 0,
            created_at TEXT DEFAULT(datetime('now','localtime'))
        );
        CREATE TABLE IF NOT EXISTS training_questions(
            id INTEGER PRIMARY KEY AUTOINCREMENT, module_id INTEGER,
            question_type TEXT DEFAULT 'mcq', question_text TEXT NOT NULL,
            options TEXT DEFAULT '[]', correct_answer TEXT DEFAULT '',
            explanation TEXT DEFAULT '',
            created_at TEXT DEFAULT(datetime('now','localtime'))
        );
        CREATE TABLE IF NOT EXISTS training_exam_records(
            id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL,
            score INTEGER DEFAULT 0, total INTEGER DEFAULT 0,
            answers TEXT DEFAULT '{}',
            created_at TEXT DEFAULT(datetime('now','localtime'))
        );
    """)
    # Create default admin (only if not exists)
    try:
        ph = hashlib.sha256(ADMIN_PWD.encode()).hexdigest()
        existing = await db_fetchone(db, "SELECT id FROM users WHERE username='admin'")
        if not existing:
            await db.execute("INSERT INTO users(username,password_hash,role,email) VALUES(?,?,'admin','admin@ruanan.com')", ('admin', ph))
    except: pass
    # Migrate: add status column to customer_users if missing
    try:
        await db.execute("ALTER TABLE customer_users ADD COLUMN status TEXT DEFAULT 'active'")
    except: pass
    # Migrate: add new customer_users columns
    for col in [("contact_name","TEXT DEFAULT "),("position","TEXT DEFAULT "),("industry","TEXT DEFAULT "),("valid_from","TEXT DEFAULT "),("valid_days","INTEGER DEFAULT 365"),("file_urls","TEXT DEFAULT """)]:
        try: await db.execute(f"ALTER TABLE customer_users ADD COLUMN {col[0]} {col[1]}")
        except: pass
    # Seed default data if empty
    await seed_data(db)
    # Clean expired tokens
    try:
        expire_time = (datetime.now() - timedelta(hours=TOKEN_EXPIRE_HOURS)).strftime('%Y-%m-%d %H:%M:%S')
        await db.execute("DELETE FROM api_tokens WHERE created_at < ?", (expire_time,))
    except: pass
    await db.commit()
    await db.close()

async def seed_data(db):
    """Seed default articles, cases, and materials if tables are empty"""
    now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    await _seed_training(db, now)
    await _seed_kb(db, now)

async def _seed_training(db, now):
    """Seed 7 product training modules + 28 questions"""
    try:
        c = (await db.execute("SELECT COUNT(*) FROM training_modules")).fetchone()[0]
    except: c = 0
    if c > 0: return

    products = [
        ("SAST", "软安SAST 静态代码质量与安全检测", "静兮", """
<h3>产品概述</h3><p>软安SAST（静兮）是一款编译型静态代码质量与安全检测工具，支持18+语言，跨文件跨函数捕获能力强，提供AI智能修复。C/C++误报率低于10%，支持MISRA/CERT/GJB多重编码规范。</p>
<h3>核心能力</h3><ul><li>18+语言支持：C/C++、Java、C#、Python、Go等</li><li>编译级分析：跨文件跨函数深度检测，误报率行业领先</li><li>AI智能修复：一键修复常见代码安全缺陷</li><li>增量秒级扫描：适合CI/CD流水线集成</li><li>多标准合规：MISRA C/C++、CERT、GJB 8114/5369</li><li>中文合规报告：一键生成满足行业标准的检测报告</li></ul>
<h3>竞争优势</h3><ul><li>对标Coverity，C/C++误报率<10%</li><li>自主可控，支持信创环境离线部署</li><li>中文团队深度支持，响应速度远超海外厂商</li></ul>
<h3>适用场景</h3><ul><li>汽车软件满足ISO 26262/ASPICE功能安全编码规范</li><li>军工涉密项目满足GJB 8114(软件测试)和GJB 5369(软件安全)</li><li>金融关键系统满足等保2.0三级软件安全要求</li></ul>"""),
        ("SCA", "软安SCA 源代码软件成分分析", "源兮", """
<h3>产品概述</h3><p>软安SCA（源兮）是源代码软件成分分析工具，支持20+语言，拥有国内顶级100T+组件数据库。Java误报率趋近0%，C/C++误报率低于10%，配备AI智能助手。</p>
<h3>核心能力</h3><ul><li>20+语言支持：Java、Python、C/C++、JavaScript/TypeScript等</li><li>100T+组件数据库：涵盖NVD/CNVD/CNNVD三大漏洞库</li><li>Java 0%误报率：精准组件识别，无虚假告警</li><li>AI智能助手：自然语言查询，组件风险自动分析</li><li>SBOM自动生成：SPDX/CycloneDX双格式支持</li><li>许可证合规：2600+许可证识别，传染性风险预警</li></ul>
<h3>竞争优势</h3><ul><li>对标Blackduck，Java误报率0%</li><li>国内最大组件知识库，国产软件覆盖全</li><li>供应链投毒检测，事前预警</li></ul>
<h3>适用场景</h3><ul><li>金融行业Log4j级漏洞72小时应急响应</li><li>出海企业满足欧盟CRA法规SBOM要求</li><li>供应商准入审查：交付代码附带SBOM和SCA审计报告</li></ul>"""),
        ("BAT", "软安BAT 二进制安全检测", "固兮", """
<h3>产品概述</h3><p>软安BAT（固兮）是二进制安全检测工具，支持100+格式解包引擎，无需源码即可进行深度安全分析。覆盖通信安全、IAC安全、敏感数据识别、加密算法识别。</p>
<h3>核心能力</h3><ul><li>100+格式解包：覆盖固件/镜像/二进制文件</li><li>通信安全检测：协议栈安全审计、中间人攻击检测</li><li>IAC安全分析：身份认证、授权、审计安全</li><li>敏感数据识别：硬编码密钥、证书、个人信息</li><li>加密算法识别：国密SM2/3/4、DES/AES/RSA等</li><li>AI智能助手：自动生成漏洞分析报告</li></ul>
<h3>竞争优势</h3><ul><li>对标Cybellum，100+格式覆盖</li><li>无需源码即可分析，适合黑盒场景</li><li>芯片级固件深度分析（BootROM/安全启动链）</li></ul>
<h3>适用场景</h3><ul><li>车载ECU/域控固件安全审计</li><li>IoT设备固件出厂前安全检测</li><li>供应链第三方设备固件安全评估</li></ul>"""),
        ("FUZZ", "软安Fuzz 黑盒协议模糊测试", "侦兮", """
<h3>产品概述</h3><p>软安Fuzz（侦兮）是黑盒协议模糊测试工具，50+协议覆盖，由国外顶级安全团队研发。汽车行业全覆盖，支持CAN/CANFD/汽车以太网。</p>
<h3>核心能力</h3><ul><li>50+协议支持：CAN/CANFD、车载以太网、蓝牙/WiFi/5G</li><li>工业协议：Modbus/MQTT、DNP3、IEC 61850、OPC UA</li><li>文件Fuzz：PDF/图片/视频等常见格式</li><li>10万+用例库：自动化变异与智能种子生成</li><li>ISO 21434合规：满足汽车网络安全工程标准</li><li>GB 44495合规：满足国内汽车软件安全国标</li></ul>
<h3>竞争优势</h3><ul><li>国外顶级安全团队研发，汽车行业经验丰富</li><li>汽车以太网(SOME/IP/DoIP)深度支持</li><li>覆盖IT/OT/IoT全场景</li></ul>
<h3>适用场景</h3><ul><li>整车CAN网络模糊测试</li><li>充电桩/电池管理系统(BMS)协议测试</li><li>工业控制系统PLC/SCADA协议安全测试</li></ul>"""),
        ("MST", "软安MST 大模型安全检测", "智兮", """
<h3>产品概述</h3><p>软安MST（智兮）是大模型全生命周期安全检测平台，覆盖基座溯源、漏洞检测、知识产权、Skill安全和智能体安全。</p>
<h3>核心能力</h3><ul><li>大模型基座溯源：模型供应链透明化</li><li>安全漏洞检测：提示注入、越狱、幻觉、数据泄露</li><li>知识产权检测：训练数据版权和许可证合规</li><li>Skill安全：大模型工具调用安全分析</li><li>智能体链路安全：多智能体协作安全审计</li><li>合规评估：生成式AI管理办法自评估</li></ul>
<h3>竞争优势</h3><ul><li>国内首批大模型安全专项检测工具</li><li>覆盖AI全生命周期（训练→部署→运营）</li><li>支持信创环境部署</li></ul>
<h3>适用场景</h3><ul><li>金融AI大模型安全评估与备案</li><li>政务大模型应用安全检测</li><li>具身智能设备LLM推理接口安全测试</li></ul>"""),
        ("CodingHawk", "软安Coding Review 代码审计智能体", "Hawk", """
<h3>产品概述</h3><p>软安CodingHawk（Hawk）是结合SAST底座的大模型驱动代码审计智能体。C/C++表现突出，支持AI自动修复和自然语言代码查询。</p>
<h3>核心能力</h3><ul><li>SAST底座+大模型引擎：深度代码理解与审计</li><li>智能化代码审计：识别复杂业务逻辑缺陷</li><li>AI自动修复建议：自动生成修复代码</li><li>C/C++表现突出：对底层代码有深度理解</li><li>自然语言查询：用中文描述问题，AI定位代码</li><li>安全编码助手：开发阶段实时安全提示</li></ul>
<h3>竞争优势</h3><ul><li>SAST底座确保分析深度，大模型提升理解广度</li><li>按用户数弹性计费，成本可控</li><li>支持私有化部署，代码不出企业</li></ul>
<h3>适用场景</h3><ul><li>C/C++遗留代码智能化审计与重构</li><li>开发团队安全左移（DevSecOps集成）</li><li>安全团队代码审查效率提升</li></ul>"""),
        ("GuardFox", "软安GuardFox AI漏洞分析验证", "洞兮", """
<h3>产品概述</h3><p>软安GuardFox（洞兮）是AI驱动的漏洞分析验证平台，专注于CVE验证、POC自动生成与验证、漏洞优先级评估，大幅提升安全团队分析效率。</p>
<h3>核心能力</h3><ul><li>CVE漏洞验证：自动化验证CVE漏洞是否存在</li><li>POC自动生成：AI生成漏洞验证POC代码</li><li>POC验证：在安全环境中验证POC有效性</li><li>漏洞优先级评估：基于CVSS+实际环境影响评估</li><li>漏洞复现：自动化漏洞复现流程</li><li>集成工单系统：漏洞→工单→修复闭环</li></ul>
<h3>竞争优势</h3><ul><li>AI驱动，自动化程度高</li><li>与SAST/SCA产品联动形成完整安全闭环</li><li>提供漏洞修复优先级量化排序</li></ul>
<h3>适用场景</h3><ul><li>安全运营团队每日漏洞处置优先级评估</li><li>应急响应：新CVE快速评估影响面</li><li>渗透测试后漏洞验证和报告生成</li></ul>""")
    ]

    for i, (pid, title, brand, content) in enumerate(products):
        await db.execute(
            "INSERT INTO training_modules(product_id,title,content,group_name,sort_order) VALUES(?,?,?,?,?)",
            (pid, title, content, "产品知识", i + 1))

    # Seed MCQ questions (4 per product = 28 total)
    mcq_questions = [
        # SAST
        (1, "mcq", "软安SAST对标以下哪个国际竞品？", '["Coverity","Blackduck","Cybellum","SonarQube"]', "0", "软安SAST对标Coverity，提供编译级静态代码分析能力"),
        (1, "mcq", "软安SAST支持多少种编程语言？", '["8种","12种","18种以上","25种"]', "2", "软安SAST支持18种以上编程语言"),
        (1, "mcq", "软安SAST的C/C++误报率是多少？", '["低于5%","低于10%","低于15%","低于20%"]', "1", "软安SAST的C/C++误报率低于10%，行业领先"),
        (1, "mcq", "以下哪个不是软安SAST支持的编码规范？", '["MISRA C/C++","CERT","PCI DSS","GJB 8114"]', "2", "PCI DSS是支付安全标准，非编码规范。软安SAST支持MISRA/CERT/GJB等"),
        # SCA
        (2, "mcq", "软安SCA的对标竞品是？", '["Coverity","Blackduck","Cybellum","Anchore"]', "1", "软安SCA对标Blackduck，提供源代码软件成分分析能力"),
        (2, "mcq", "软安SCA的Java误报率是多少？", '["低于5%","低于10%","趋近0%","低于3%"]', "2", "软安SCA的Java误报率趋近0%，业界领先"),
        (2, "mcq", "软安SCA组件数据库规模有多大？", '["10T+","50T+","100T+","500T+"]', "2", "软安SCA拥有国内顶级的100T+组件数据库"),
        (2, "mcq", "SBOM支持的两种标准格式是？", '["JSON和XML","SPDX和CycloneDX","PDF和HTML","CPE和CVE"]', "1", "软安SCA支持SPDX和CycloneDX两种标准SBOM格式"),
        # BAT
        (3, "mcq", "软安BAT支持多少种文件格式解包？", '["50+","100+","200+","500+"]', "1", "软安BAT支持100+格式解包引擎"),
        (3, "mcq", "软安BAT对标以下哪个竞品？", '["Coverity","Blackduck","Cybellum","Veracode"]', "2", "软安BAT对标Cybellum，专注二进制安全检测"),
        (3, "mcq", "以下哪项不是软安BAT的检测能力？", '["通信安全检测","IAC安全分析","源代码审计","加密算法识别"]', "2", "软安BAT是二进制(非源码)检测工具，不进行源代码审计"),
        (3, "mcq", "软安BAT可以检测以下哪些内容？", '["硬编码密钥","固件后门","安全启动链完整性","以上全部"]', "3", "软安BAT覆盖以上全部检测能力"),
        # FUZZ
        (4, "mcq", "软安Fuzz支持多少种协议？", '["20+","30+","50+","100+"]', "2", "软安Fuzz支持50+协议覆盖"),
        (4, "mcq", "以下哪个汽车协议是软安Fuzz支持的？", '["CAN/CANFD","以太网AVB","MOST","以上全部"]', "3", "软安Fuzz支持以上全部汽车协议"),
        (4, "mcq", "软安Fuzz满足哪个汽车安全标准？", '["ISO 9001","ISO 21434","ISO 14001","ISO 27000"]', "1", "软安Fuzz满足ISO 21434汽车网络安全工程标准"),
        (4, "mcq", "软安Fuzz有多少预置测试用例？", '["1万+","5万+","10万+","50万+"]', "2", "软安Fuzz预置10万+测试用例库"),
        # MST
        (5, "mcq", "以下哪个不是大模型安全检测内容？", '["提示注入检测","越狱检测","固件分析","知识产权检测"]', "2", "固件分析属于BAT产品范围，非MST"),
        (5, "mcq", "软安MST覆盖大模型哪些阶段？", '["仅训练阶段","仅部署阶段","全生命周期","仅推理阶段"]', "2", "软安MST覆盖大模型全生命周期安全检测"),
        (5, "mcq", "Skill安全检测主要针对？", '["大模型工具调用安全","代码质量","网络协议","数据库安全"]', "0", "Skill安全主要检测大模型工具调用(函数调用)的安全性"),
        (5, "mcq", "软安MST是否支持信创环境部署？", '["不支持","仅支持云端","支持信创环境离线部署","仅支持Windows"]', "2", "软安MST支持信创环境离线部署"),
        # CodingHawk
        (6, "mcq", "CodingHawk的底座是什么？", '["SCA","SAST","BAT","MST"]', "1", "CodingHawk以SAST为底座，结合大模型引擎"),
        (6, "mcq", "CodingHawk在哪类代码上表现最突出？", '["Java","Python","C/C++","Go"]', "2", "CodingHawk在C/C++代码审计上表现突出"),
        (6, "mcq", "CodingHawk的计费方式是？", '["按年许可","按用户/月","一次买断","按扫描行数"]', "1", "CodingHawk按用户/月弹性计费，0.8万/用户/月"),
        (6, "mcq", "CodingHawk支持哪种交互方式？", '["仅API","自然语言查询","仅图形界面","命令行"]', "1", "CodingHawk支持自然语言查询代码"),
        # GuardFox
        (7, "mcq", "GuardFox的核心功能是？", '["代码审计","CVE验证与POC生成","固件分析","协议测试"]', "1", "GuardFox聚焦CVE漏洞验证与POC自动生成"),
        (7, "mcq", "GuardFox的漏洞优先级评估基于？", '["仅CVSS评分","CVSS+实际环境影响","仅影响范围","用户主观判断"]', "1", "GuardFox基于CVSS评分+实际环境影响综合评估漏洞优先级"),
        (7, "mcq", "GuardFox与哪个产品联动形成闭环？", '["仅SCA","SAST+SCA","仅BAT","仅Fuzz"]', "1", "GuardFox与SAST/SCA产品联动，形成检测→验证→修复完整闭环"),
        (7, "mcq", "GuardFox的POC在哪里验证？", '["生产环境","安全隔离环境","开发环境","客户自行验证"]', "1", "GuardFox在安全隔离环境中验证POC，避免影响生产"),
    ]

    for (module_id, qtype, text, opts, answer, explanation) in mcq_questions:
        await db.execute(
            "INSERT INTO training_questions(module_id,question_type,question_text,options,correct_answer,explanation) VALUES(?,?,?,?,?,?)",
            (module_id, qtype, text, opts, answer, explanation))

    # Seed essay questions (1 per product = 7 total)
    essay_questions = [
        (1, "essay", "请简述软安SAST相比Coverity的三大核心优势，以及适合推荐给哪些类型的客户。", "", "从国内自主可控(信创/涉密离线)、中文支持与响应速度、C/C++误报率对比等角度回答。适用客户：军工、汽车、关键基础设施等需离线部署的行业。"),
        (2, "essay", "客户询问\"我们的Java项目用了大量开源组件，如何保证没有Log4j这类高危漏洞\"，请用SCA的能力回答。", "", "强调Java 0%误报率、100T+组件数据库涵盖NVD/CNVD/CNNVD、供应链投毒检测、自动SBOM生成与持续监控等能力。"),
        (3, "essay", "某汽车Tier1供应商需要向OEM交付代码安全审计报告，请设计推荐组合方案。", "", "SAST+BAT+Fuzz组合：SAST做源码分析交付审计报告、BAT做ECU固件检测、Fuzz做CAN/车载以太网协议测试，满足ISO 21434和R155。"),
        (4, "essay", "请列出软安Fuzz在汽车行业的三个典型应用场景及其价值。", "", "1.CAN总线Fuzz测试→发现ECU通信漏洞；2.OTA升级包Fuzz→确保升级安全；3.车载以太网SOME/IP协议测试→满足R155要求。价值：降低召回风险、通过OEM审计、满足法规。"),
        (5, "essay", "某金融机构计划上线AI客服大模型，需要满足监管要求，请推荐安全方案。", "", "MST+CodingHawk组合：MST做提示注入/越狱/数据泄露检测满足生成式AI管理办法；CodingHawk做AI相关代码的安全审计。配合GuardFox进行持续漏洞监控。"),
        (6, "essay", "CodingHawk与SAST的区别是什么？什么场景下应该推荐CodingHawk？", "", "SAST是规则引擎(确定性检测)，CodingHawk是SAST+大模型(AI理解增强)。推荐场景：遗留C/C++代码审计、自然语言查询需求、开发团队安全左移、需AI修复建议的客户。"),
        (7, "essay", "客户问\"GuardFox能自动帮我修漏洞吗？\"请回答并说明GuardFox的定位。", "", "GuardFox定位是漏洞验证分析(非修复)。核心价值：自动验证CVE是否真的影响我们、自动生成POC验证漏洞可利用性、优先级量化排序告诉先修哪个。需配合SAST/SCA完成检测→验证→修复闭环。"),
    ]

    for (module_id, qtype, text, answer, explanation) in essay_questions:
        await db.execute(
            "INSERT INTO training_questions(module_id,question_type,question_text,options,correct_answer,explanation) VALUES(?,?,?,?,?,?)",
            (module_id, qtype, text, "[]", answer, explanation))

async def _seed_kb(db, now):
    """Seed default KB articles if table is empty"""
    try:
        c = (await db.execute("SELECT COUNT(*) FROM kb_articles")).fetchone()[0]
    except: c = 0
    if c > 0: return

    kb_articles = [
        ("SAST", "产品文档", "SAST快速入门指南", "本文介绍软安SAST的安装部署、首次扫描配置和结果解读", "<h3>SAST快速入门</h3><p>本文档帮助用户在30分钟内完成SAST的安装、配置和首次扫描。</p><h4>步骤1：环境准备</h4><p>确保系统满足最低配置要求：8核CPU、16GB内存、100GB可用磁盘空间。支持Linux/Windows/信创环境。</p><h4>步骤2：安装部署</h4><p>下载安装包后，执行安装脚本。支持Docker部署和裸机部署两种方式。</p><h4>步骤3：创建首个项目</h4><p>登录Web控制台，点击\"新建项目\"，选择代码语言和扫描规则集(MISRA/CERT/GJB)。</p><h4>步骤4：查看扫描结果</h4><p>扫描完成后，控制台展示缺陷列表、严重等级分布、合规状态。支持导出中文PDF报告。</p>"),
        ("SCA", "产品文档", "SCA组件分析原理与最佳实践", "深入理解SCA的组件识别机制和SBOM生成流程", "<h3>SCA组件分析原理</h3><p>软安SCA通过多种技术手段识别开源组件：依赖文件解析(pom.xml/package.json/requirements.txt等)、二进制指纹匹配、代码片段相似度检测。</p><h4>SBOM生成最佳实践</h4><p>1. 在CI/CD流水线中集成SCA扫描步骤<br>2. 每次发版前自动生成SBOM<br>3. 将SBOM归档作为合规证据<br>4. 定期对比SBOM变化，追踪新增组件</p>"),
        ("BAT", "产品文档", "二进制固件安全检测操作手册", "详细说明BAT支持的文件格式、解包流程和安全检测项", "<h3>BAT操作手册</h3><h4>支持的文件格式</h4><p>固件镜像(.bin/.hex/.elf)、文件系统镜像(ext4/FAT/NTFS)、压缩包(.zip/.tar.gz)、Android OTA包、RTOS固件等100+格式。</p><h4>分析流程</h4><p>1. 上传固件文件(≤20GB)<br>2. 自动识别格式并解包<br>3. 提取文件系统、二进制可执行文件<br>4. 逐项安全检测(通信/IAC/敏感数据/加密算法)<br>5. 生成安全分析报告</p>"),
        ("FUZZ", "使用技巧", "汽车CAN总线Fuzz测试实战", "以某车型CAN网络为例，演示Fuzz测试全流程", "<h3>CAN总线Fuzz测试实战</h3><h4>测试准备</h4><p>1. 获取CAN DBC文件(定义CAN消息格式)<br>2. 连接CAN接口硬件(Vector/CANable/PCAN)<br>3. 配置Fuzz测试参数</p><h4>测试执行</h4><p>选择CAN协议模板→导入DBC文件→选择Fuzz策略(随机/变异/智能)→启动测试。系统自动记录异常响应、ECU重启、通信中断等异常。</p><h4>结果分析</h4><p>对异常CAN ID进行深入分析，确认是否可利用。生成ISO 21434合规测试报告。</p>"),
        ("MST", "产品文档", "大模型安全检测配置指南", "介绍如何针对不同的大模型类型配置安全检测策略", "<h3>MST配置指南</h3><h4>支持的模型类型</h4><p>ChatGPT/Claude/Gemini等闭源大模型API、Llama/Qwen/DeepSeek等开源模型、自定义微调模型。</p><h4>检测策略配置</h4><p>1. 提示注入检测：自动生成对抗性提示词<br>2. 越狱检测：尝试绕过安全限制<br>3. 数据泄露评估：检测模型是否泄露训练数据<br>4. 知识产权检测：评估模型训练数据版权合规</p>"),
        ("SAST", "使用技巧", "SAST增量扫描优化技巧", "如何在CI/CD中配置增量扫描，将扫描时间从分钟缩短到秒级", "<h3>SAST增量扫描优化</h3><h4>原理</h4><p>SAST增量扫描仅分析自上次扫描以来变更的文件及其影响范围，而非全量扫描。</p><h4>配置方法</h4><p>在Jenkins/GitLab CI/GitHub Actions中配置增量扫描参数：<br>1. 指定Git diff范围<br>2. 开启依赖分析(变更文件影响的调用链)<br>3. 设置超时阈值(超过N分钟自动降级为变更文件扫描)</p><h4>效果</h4><p>典型Java项目全量扫描30分钟→增量扫描30秒以内。</p>"),
        ("CodingHawk", "最佳实践", "如何使用CodingHawk审计遗留C/C++代码", "针对军工/汽车行业遗留代码的审计方法论", "<h3>遗留C/C++代码审计方法论</h3><h4>挑战</h4><p>90年代至今的C/C++代码：缺乏文档、函数规模大(数千行)、指针密集、汇编混编。</p><h4>CodingHawk优势</h4><p>1. AI理解代码意图(超越规则匹配)<br>2. 自然语言查询：\"找出所有可能导致缓冲区溢出的指针操作\"<br>3. 跨文件分析：追踪指针在多文件间的传递<br>4. AI生成注释和文档</p><h4>审计流程</h4><p>导入代码→AI自动生成代码地图→按风险等级排序→逐一审计→AI辅助修复→输出审计报告</p>"),
        ("SCA", "最佳实践", "开源许可证合规管理实战", "如何建立企业级开源许可证合规管理体系", "<h3>开源许可证合规管理</h3><h4>许可证风险分级</h4><p>高风险(GPL/AGPL)：传染性强，商业产品需谨慎<br>中风险(LGPL/MPL)：部分传染<br>低风险(MIT/Apache/BSD)：商业友好</p><h4>SCA许可证管理流程</h4><p>1. 自动识别项目所有组件的许可证<br>2. 标记传染性许可证组件<br>3. 生成许可证合规报告<br>4. 设置许可证策略(自动阻断高风险组件引入)</p>"),
        ("BAT", "使用技巧", "固件安全检测中的常见误报处理", "分析BAT检测中常见误报类型及排查方法", "<h3>常见误报及排查</h3><h4>加密算法误报</h4><p>原因：常量数据被误识别为密钥。排查：检查是否包含密钥特征(熵值、结构)。</p><h4>硬编码密钥误报</h4><p>原因：测试代码中的示例密钥。排查：确认代码路径是否在生产环境中可达。</p><h4>后门检测误报</h4><p>原因：调试接口被标记为后门。排查：确认接口在生产固件中是否可访问。</p>"),
        ("GuardFox", "使用技巧", "如何利用GuardFox进行每日漏洞优先级排序", "安全运营团队每日使用GuardFox的工作流程", "<h3>每日漏洞处置流程</h3><h4>Step 1：获取当日新CVE</h4><p>GuardFox自动同步NVD/CNVD/CNNVD当日新增CVE。</p><h4>Step 2：自动验证</h4><p>针对企业产品清单中使用的组件，自动验证CVE是否影响。</p><h4>Step 3：优先级排序</h4><p>基于CVSS评分×实际环境影响×资产重要性，输出TOP N排序。</p><h4>Step 4：生成工单</h4><p>对高优先级漏洞自动创建修复工单，分配给对应开发团队。</p>"),
        ("MST", "最佳实践", "金融行业AI大模型安全合规路径", "从监管视角解析金融AI大模型的安全合规要求与实施路径", "<h3>金融AI大模型安全合规路径</h3><h4>监管框架</h4><p>1. 生成式AI服务管理暂行办法<br>2. 金融行业AI应用安全评估指引<br>3. 个人信息保护法</p><h4>实施路径</h4><p>Step1: 模型备案(基座溯源+安全评估报告)<br>Step2: 安全检测(提示注入/越狱/数据泄露)<br>Step3: 持续监控(模型更新后重新评估)<br>Step4: 应急响应(发现安全问题→模型下线→修复→重新上线)</p>"),
        ("CodingHawk", "使用技巧", "CodingHawk自然语言查询技巧", "20个实用自然语言查询示例，提升代码审计效率", "<h3>自然语言查询技巧</h3><h4>安全类查询</h4><p>\"找出所有SQL拼接的代码\"<br>\"查找没有做输入校验的API接口\"<br>\"找出硬编码的密码和密钥\"</p><h4>质量类查询</h4><p>\"找出圈复杂度超过20的函数\"<br>\"列出所有未处理返回值的函数调用\"<br>\"查找可能空指针引用的代码\"</p><h4>合规类查询</h4><p>\"检查是否使用了禁用的加密算法DES/MD5\"<br>\"找出所有直接操作内存的代码\"</p>"),
    ]

    for (product_id, category, title, summary, content) in kb_articles:
        await db.execute(
            "INSERT INTO kb_articles(title,content,summary,category,product_id,author,tags) VALUES(?,?,?,?,?,?,?)",
            (title, content, summary, category, product_id, "软安科技", product_id))

# ═══════════════════════════════════════════════════
# AUTH APIS (existing, kept unchanged)
# ═══════════════════════════════════════════════════

@app.get("/api/captcha")
async def get_captcha():
    captcha_id, question, _ = generate_captcha()
    return {"captcha_id": captcha_id, "question": question}

@app.post("/api/login")
async def login(request: Request, username: str = Form(...), password: str = Form(...),
                captcha_id: str = Form(""), captcha_answer: str = Form("")):
    client_ip = request.client.host if request.client else "unknown"
    # captcha verified client-side, frontend handles it
    # if not verify_captcha(captcha_id, captcha_answer):
    #     raise HTTPException(400, "验证码错误或已过期，请刷新重试")
    if not check_login_rate(client_ip):
        raise HTTPException(429, "登录尝试过于频繁，请5分钟后再试")
    record_login_attempt(client_ip)
    username = safe_str(username, 50)
    if not username or not password: raise HTTPException(400, "用户名和密码不能为空")
    db = await get_db()
    try:
        ph = hashlib.sha256(password.encode()).hexdigest()
        row = await db_fetchone(db, "SELECT * FROM users WHERE username=? AND password_hash=?", (username, ph))
        if not row: raise HTTPException(401, "用户名或密码错误")
        token = secrets.token_hex(32)
        await db.execute("INSERT INTO api_tokens(user_id,token) VALUES(?,?)", (row["id"], token))
        await db.commit()
        return {"token": token, "username": row["username"], "role": row["role"],
                "email": row["email"], "phone": row["phone"], "company": row["company"]}
    except HTTPException: raise
    finally: await db.close()

@app.post("/api/register")
async def register(username: str = Form(...), password: str = Form(...), email: str = Form(""),
                   phone: str = Form(""), company: str = Form(""), role: str = Form("user")):
    uname_err = validate_username(username)
    if uname_err: raise HTTPException(400, uname_err)
    pwd_err = validate_password_strength(password)
    if pwd_err: raise HTTPException(400, pwd_err)
    email, phone, company = safe_str(email, 200), safe_str(phone, 30), safe_str(company, 200)
    r = safe_str(role, 20)
    if r not in ('user', 'partner'): r = 'user'
    db = await get_db()
    try:
        existing = await db_fetchone(db, "SELECT id FROM users WHERE username=?", (username,))
        if existing: raise HTTPException(400, "用户名已存在")
        ph = hashlib.sha256(password.encode()).hexdigest()
        cur = await db.execute(
            "INSERT INTO users(username,password_hash,email,phone,company,role) VALUES(?,?,?,?,?,?)",
            (username, ph, email, phone, company, r))
        await db.commit(); uid = cur.lastrowid
        token = secrets.token_hex(32)
        await db.execute("INSERT INTO api_tokens(user_id,token) VALUES(?,?)", (uid, token))
        await db.commit()
        return {"token": token, "username": username, "role": r}
    except HTTPException: raise
    except Exception as e:
        if "UNIQUE" in str(e): raise HTTPException(400, "用户名已存在")
        raise HTTPException(500, "注册失败")
    finally: await db.close()

@app.post("/api/forgot-password")
async def forgot_password(username: str = Form(...), email: str = Form(...)):
    username, email = safe_str(username, 50), safe_str(email, 200)
    if not username or not email: raise HTTPException(400, "用户名和邮箱不能为空")
    db = await get_db()
    try:
        row = await db_fetchone(db, "SELECT * FROM users WHERE username=? AND email=?", (username, email))
        if not row: raise HTTPException(404, "未找到匹配的用户名和邮箱")
        new_pwd = secrets.token_hex(10)
        ph = hashlib.sha256(new_pwd.encode()).hexdigest()
        await db.execute("UPDATE users SET password_hash=? WHERE id=?", (ph, row["id"]))
        await db.commit()
        return {"message": "密码已重置，新密码为: " + new_pwd + "。请使用新密码登录后立即修改密码。"}
    except HTTPException: raise
    finally: await db.close()

@app.get("/api/me")
async def me(request: Request):
    user = await get_auth_user(request)
    if not user: return {"username": "guest", "role": "guest"}
    return {k: user[k] for k in ("id","username","role","email","phone","company","department","region","avatar_url")}

# ═══════════════════════════════════════════════════
# LEADS (existing)
# ═══════════════════════════════════════════════════
@app.post("/api/leads")
async def save_lead(request: Request, company: str = Form(""), contact: str = Form(""),
                    title: str = Form(""), email: str = Form(""), phone: str = Form(""),
                    address: str = Form(""), industry: str = Form(""), scenes: str = Form(""),
                    budget: str = Form(""), pains: str = Form(""), custom_pain: str = Form(""),
                    project_budget: str = Form(""), team_size: str = Form(""),
                    languages: str = Form(""), timeline: str = Form(""),
                    type: str = Form(""), note: str = Form(""), user_id: int = Form(0)):
    db = await get_db()
    await db.execute(
        "INSERT INTO leads(user_id,company,contact,title,email,phone,address,industry,scenes,budget,pains,custom_pain,project_budget,team_size,languages,timeline,type,note) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (user_id, company, contact, title, email, phone, address, industry, scenes, budget, pains, custom_pain, project_budget, team_size, languages, timeline, type, note))
    await db.commit(); await db.close()
    return {"ok": True}

@app.get("/api/leads")
async def list_leads(request: Request):
    await require_admin(request)
    db = await get_db()
    rows = await db_fetchall(db, "SELECT l.*, u.username FROM leads l LEFT JOIN users u ON l.user_id=u.id ORDER BY l.submit_time DESC LIMIT 200")
    await db.close()
    return [dict(r) for r in rows]

# ═══════════════════════════════════════════════════
# ARTICLES (public read, admin write)
# ═══════════════════════════════════════════════════
@app.get("/api/articles")
async def list_articles(category: str = "", search: str = "", limit: int = 20):
    db = await get_db()
    sql = "SELECT * FROM articles WHERE published=1"
    params = []
    if category:
        sql += " AND category=?"; params.append(category)
    if search:
        sql += " AND (title LIKE ? OR content LIKE ? OR tags LIKE ?)"
        params.extend([f"%{search}%", f"%{search}%", f"%{search}%"])
    sql += " ORDER BY created_at DESC LIMIT ?"; params.append(limit)
    rows = await db_fetchall(db, sql, params)
    await db.close()
    return [dict(r) for r in rows]

@app.get("/api/articles/{aid}")
async def get_article(aid: int):
    db = await get_db()
    row = await db_fetchone(db, "SELECT * FROM articles WHERE id=? AND published=1", (aid,))
    await db.close()
    if not row: raise HTTPException(404, "文章不存在")
    return dict(row)

@app.post("/api/articles")
async def create_article(request: Request, title: str = Form(...), content: str = Form(""),
                         summary: str = Form(""), category: str = Form("行业洞察"),
                         tags: str = Form(""), author: str = Form("软安科技"), published: int = Form(1)):
    await require_admin(request)
    db = await get_db()
    cur = await db.execute(
        "INSERT INTO articles(title,content,summary,category,tags,author,published,updated_at) VALUES(?,?,?,?,?,?,?,datetime('now','localtime'))",
        (safe_str(title,200), safe_str(content,50000), safe_str(summary,500), safe_str(category,50), safe_str(tags,200), safe_str(author,50), published))
    await db.commit()
    aid = cur.lastrowid
    await db.close()
    return {"id": aid, "ok": True}

@app.put("/api/articles/{aid}")
async def update_article(aid: int, request: Request, title: str = Form(""), content: str = Form(""),
                         summary: str = Form(""), category: str = Form(""), tags: str = Form(""),
                         author: str = Form(""), published: int = Form(None)):
    await require_admin(request)
    db = await get_db()
    existing = await db_fetchone(db, "SELECT * FROM articles WHERE id=?", (aid,))
    if not existing: await db.close(); raise HTTPException(404, "文章不存在")
    updates = []
    params = []
    if title: updates.append("title=?"); params.append(safe_str(title, 200))
    if content: updates.append("content=?"); params.append(safe_str(content, 50000))
    if summary: updates.append("summary=?"); params.append(safe_str(summary, 500))
    if category: updates.append("category=?"); params.append(safe_str(category, 50))
    if tags: updates.append("tags=?"); params.append(safe_str(tags, 200))
    if author: updates.append("author=?"); params.append(safe_str(author, 50))
    if published is not None: updates.append("published=?"); params.append(published)
    if updates:
        updates.append("updated_at=datetime('now','localtime')")
        params.append(aid)
        await db.execute(f"UPDATE articles SET {','.join(updates)} WHERE id=?", params)
        await db.commit()
    await db.close()
    return {"ok": True}

@app.delete("/api/articles/{aid}")
async def delete_article(aid: int, request: Request):
    await require_admin(request)
    db = await get_db()
    await db.execute("DELETE FROM articles WHERE id=?", (aid,))
    await db.commit()
    await db.close()
    return {"ok": True}

# ═══════════════════════════════════════════════════
# CASES (public read, admin write)
# ═══════════════════════════════════════════════════
@app.get("/api/cases")
async def list_cases(industry: str = "", limit: int = 50):
    db = await get_db()
    sql = "SELECT * FROM cases WHERE published=1"
    params = []
    if industry:
        sql += " AND industry=?"; params.append(industry)
    sql += " ORDER BY created_at DESC LIMIT ?"; params.append(limit)
    rows = await db_fetchall(db, sql, params)
    await db.close()
    return [dict(r) for r in rows]

@app.post("/api/cases")
async def create_case(request: Request, title: str = Form(...), industry: str = Form(""),
                      tag: str = Form(""), description: str = Form(""), metric: str = Form(""),
                      content: str = Form(""), video_url: str = Form(""), cover_url: str = Form(""),
                      published: int = Form(1)):
    await require_admin(request)
    db = await get_db()
    cur = await db.execute(
        "INSERT INTO cases(title,industry,tag,description,metric,content,video_url,cover_url,published) VALUES(?,?,?,?,?,?,?,?,?)",
        (safe_str(title,200), safe_str(industry,50), safe_str(tag,50), safe_str(description,1000),
         safe_str(metric,200), safe_str(content,10000), safe_str(video_url,500), safe_str(cover_url,500), published))
    await db.commit(); cid = cur.lastrowid
    await db.close()
    return {"id": cid, "ok": True}

@app.put("/api/cases/{cid}")
async def update_case(cid: int, request: Request, title: str = Form(""), industry: str = Form(""),
                      tag: str = Form(""), description: str = Form(""), metric: str = Form(""),
                      content: str = Form(""), video_url: str = Form(""), cover_url: str = Form(""),
                      published: int = Form(None)):
    await require_admin(request)
    db = await get_db()
    existing = await db_fetchone(db, "SELECT * FROM cases WHERE id=?", (cid,))
    if not existing: await db.close(); raise HTTPException(404, "案例不存在")
    updates = {}
    if title: updates["title"] = safe_str(title, 200)
    if industry: updates["industry"] = safe_str(industry, 50)
    if tag: updates["tag"] = safe_str(tag, 50)
    if description: updates["description"] = safe_str(description, 1000)
    if metric: updates["metric"] = safe_str(metric, 200)
    if content: updates["content"] = safe_str(content, 10000)
    if video_url: updates["video_url"] = safe_str(video_url, 500)
    if cover_url: updates["cover_url"] = safe_str(cover_url, 500)
    if published is not None: updates["published"] = published
    if updates:
        sets = [f"{k}=?" for k in updates]
        vals = list(updates.values()) + [cid]
        await db.execute(f"UPDATE cases SET {','.join(sets)} WHERE id=?", vals)
        await db.commit()
    await db.close()
    return {"ok": True}

@app.delete("/api/cases/{cid}")
async def delete_case(cid: int, request: Request):
    await require_admin(request)
    db = await get_db()
    await db.execute("DELETE FROM cases WHERE id=?", (cid,))
    await db.commit(); await db.close()
    return {"ok": True}

# ═══════════════════════════════════════════════════
# PARTNERS
# ═══════════════════════════════════════════════════
@app.post("/api/partners/apply")
async def apply_partner(request: Request, company: str = Form(...), contact: str = Form(...),
                        phone: str = Form(...), email: str = Form(""), address: str = Form(""),
                        business_scope: str = Form("")):
    user = await require_auth(request)
    db = await get_db()
    try:
        existing = await db_fetchone(db, "SELECT * FROM partners WHERE user_id=?", (user["id"],))
        if existing: raise HTTPException(400, "您已提交过合作伙伴申请，请等待审核")
        await db.execute(
            "INSERT INTO partners(user_id,company,contact,phone,email,address,business_scope,status) VALUES(?,?,?,?,?,?,?,?)",
            (user["id"], safe_str(company,200), safe_str(contact,50), safe_str(phone,30),
             safe_str(email,200), safe_str(address,200), safe_str(business_scope,500), 'pending'))
        await db.commit()
        # Auto-upgrade user role
        await db.execute("UPDATE users SET role='partner',company=? WHERE id=?", (safe_str(company,200), user["id"]))
        await db.commit()
    except HTTPException: raise
    finally: await db.close()
    return {"ok": True, "message": "申请已提交，请等待审核"}

@app.get("/api/partners/status")
async def partner_status(request: Request):
    user = await require_auth(request)
    db = await get_db()
    try:
        row = await db_fetchone(db, "SELECT * FROM partners WHERE user_id=?", (user["id"],))
        return dict(row) if row else {"status": "not_applied"}
    finally: await db.close()

@app.get("/api/admin/partners")
async def list_partners(request: Request):
    await require_admin(request)
    db = await get_db()
    rows = await db_fetchall(db,
        "SELECT p.*, u.username, u.email as user_email FROM partners p LEFT JOIN users u ON p.user_id=u.id ORDER BY p.created_at DESC")
    await db.close()
    return [dict(r) for r in rows]

@app.put("/api/admin/partners/{pid}")
async def update_partner(pid: int, request: Request, status: str = Form("")):
    await require_admin(request)
    db = await get_db()
    if status in ('approved', 'rejected', 'pending'):
        await db.execute("UPDATE partners SET status=? WHERE id=?", (status, pid))
        if status == 'rejected':
            # Downgrade user role
            await db.execute("UPDATE users SET role='user' WHERE id=(SELECT user_id FROM partners WHERE id=?)", (pid,))
        await db.commit()
    await db.close()
    return {"ok": True}

# ═══════════════════════════════════════════════════
# OPPORTUNITIES (商机报备)
# ═══════════════════════════════════════════════════
@app.post("/api/opportunities")
async def create_opportunity(request: Request, customer_name: str = Form(...),
                             industry: str = Form(""), estimated_amount: str = Form(""),
                             products_interested: str = Form(""), notes: str = Form(""),
                             stage: str = Form("报备")):
    user = await require_partner(request)
    db = await get_db()
    try:
        # Get partner id
        partner = await db_fetchone(db, "SELECT id FROM partners WHERE user_id=? AND status='approved'", (user["id"],))
        if not partner and user["role"] != "admin":
            raise HTTPException(403, "需要已审批的合作伙伴身份")
        pid = partner["id"] if partner else 0
        cur = await db.execute(
            "INSERT INTO opportunities(partner_id,customer_name,industry,estimated_amount,products_interested,stage,notes) VALUES(?,?,?,?,?,?,?)",
            (pid, safe_str(customer_name,200), safe_str(industry,50), safe_str(estimated_amount,50),
             safe_str(products_interested,200), safe_str(stage,20), safe_str(notes,2000)))
        await db.commit(); oid = cur.lastrowid
    except HTTPException: raise
    finally: await db.close()
    return {"id": oid, "ok": True}

@app.get("/api/opportunities")
async def list_opportunities(request: Request):
    user = await require_auth(request)
    db = await get_db()
    try:
        if user["role"] == "admin":
            rows = await db_fetchall(db,
                "SELECT o.*, p.company as partner_company FROM opportunities o LEFT JOIN partners p ON o.partner_id=p.id ORDER BY o.created_at DESC")
        else:
            partner = await db_fetchone(db, "SELECT id FROM partners WHERE user_id=?", (user["id"],))
            pid = partner["id"] if partner else 0
            rows = await db_fetchall(db, "SELECT * FROM opportunities WHERE partner_id=? ORDER BY created_at DESC", (pid,))
        await db.close()
        return [dict(r) for r in rows]
    finally:
        try: await db.close()
        except: pass

@app.put("/api/opportunities/{oid}")
async def update_opportunity(oid: int, request: Request, stage: str = Form(""),
                             estimated_amount: str = Form(""), notes: str = Form("")):
    user = await require_partner(request)
    db = await get_db()
    try:
        updates = {}
        if stage: updates["stage"] = safe_str(stage, 20)
        if estimated_amount: updates["estimated_amount"] = safe_str(estimated_amount, 50)
        if notes: updates["notes"] = safe_str(notes, 2000)
        if updates:
            updates["updated_at"] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            sets = [f"{k}=?" for k in updates]
            vals = list(updates.values()) + [oid]
            await db.execute(f"UPDATE opportunities SET {','.join(sets)} WHERE id=?", vals)
            await db.commit()
    finally: await db.close()
    return {"ok": True}

# ═══════════════════════════════════════════════════
# TICKETS (技术支持工单)
# ═══════════════════════════════════════════════════
@app.post("/api/tickets")
async def create_ticket(request: Request, subject: str = Form(...), description: str = Form(""),
                        category: str = Form("技术支持"), priority: str = Form("normal")):
    user = await require_auth(request)
    db = await get_db()
    try:
        cur = await db.execute(
            "INSERT INTO tickets(user_id,subject,description,category,priority) VALUES(?,?,?,?,?)",
            (user["id"], safe_str(subject,200), safe_str(description,5000), safe_str(category,50), safe_str(priority,20)))
        await db.commit(); tid = cur.lastrowid
    finally: await db.close()
    return {"id": tid, "ok": True}

@app.get("/api/tickets")
async def list_tickets(request: Request, status: str = ""):
    user = await require_auth(request)
    db = await get_db()
    try:
        if user["role"] == "admin":
            sql = "SELECT t.*, u.username FROM tickets t LEFT JOIN users u ON t.user_id=u.id"
            params = []
            if status:
                sql += " WHERE t.status=?"; params.append(status)
            sql += " ORDER BY t.created_at DESC LIMIT 200"
            rows = await db_fetchall(db, sql, params)
        else:
            rows = await db_fetchall(db,
                "SELECT * FROM tickets WHERE user_id=? ORDER BY created_at DESC LIMIT 100", (user["id"],))
        await db.close()
        return [dict(r) for r in rows]
    finally:
        try: await db.close()
        except: pass

@app.get("/api/tickets/{tid}")
async def get_ticket(tid: int, request: Request):
    user = await require_auth(request)
    db = await get_db()
    try:
        row = await db_fetchone(db, "SELECT t.*, u.username FROM tickets t LEFT JOIN users u ON t.user_id=u.id WHERE t.id=?", (tid,))
        if not row: raise HTTPException(404, "工单不存在")
        if user["role"] != "admin" and row["user_id"] != user["id"]:
            raise HTTPException(403, "无权查看此工单")
        await db.close()
        return dict(row)
    finally:
        try: await db.close()
        except: pass

@app.put("/api/tickets/{tid}/reply")
async def reply_ticket(tid: int, request: Request, reply: str = Form(...)):
    await require_admin(request)
    db = await get_db()
    try:
        await db.execute(
            "UPDATE tickets SET reply=?, status='replied', replied_at=datetime('now','localtime') WHERE id=?",
            (safe_str(reply, 5000), tid))
        await db.commit()
    finally: await db.close()
    return {"ok": True}

@app.put("/api/tickets/{tid}/close")
async def close_ticket(tid: int, request: Request):
    user = await require_auth(request)
    db = await get_db()
    try:
        row = await db_fetchone(db, "SELECT * FROM tickets WHERE id=?", (tid,))
        if not row: raise HTTPException(404, "工单不存在")
        if user["role"] != "admin" and row["user_id"] != user["id"]:
            raise HTTPException(403, "无权操作")
        await db.execute("UPDATE tickets SET status='closed' WHERE id=?", (tid,))
        await db.commit()
    finally: await db.close()
    return {"ok": True}

# ═══════════════════════════════════════════════════
# MATERIALS (营销物料)
# ═══════════════════════════════════════════════════
@app.get("/api/materials")
async def list_materials(category: str = ""):
    db = await get_db()
    sql = "SELECT * FROM materials"
    params = []
    if category:
        sql += " WHERE category=?"; params.append(category)
    sql += " ORDER BY created_at DESC"
    rows = await db_fetchall(db, sql, params)
    await db.close()
    return [dict(r) for r in rows]

@app.post("/api/materials")
async def create_material(request: Request, title: str = Form(...), description: str = Form(""),
                          category: str = Form("产品资料"), file_url: str = Form(""),
                          file_type: str = Form("")):
    await require_admin(request)
    db = await get_db()
    try:
        cur = await db.execute(
            "INSERT INTO materials(title,description,category,file_url,file_type) VALUES(?,?,?,?,?)",
            (safe_str(title,200), safe_str(description,1000), safe_str(category,50), safe_str(file_url,500), safe_str(file_type,20)))
        await db.commit(); mid = cur.lastrowid
    finally: await db.close()
    return {"id": mid, "ok": True}

@app.delete("/api/materials/{mid}")
async def delete_material(mid: int, request: Request):
    await require_admin(request)
    db = await get_db()
    await db.execute("DELETE FROM materials WHERE id=?", (mid,))
    await db.commit(); await db.close()
    return {"ok": True}

# ═══════════════════════════════════════════════════
# FILE UPLOAD
# ═══════════════════════════════════════════════════
@app.post("/api/upload")
async def upload_file(request: Request, file: UploadFile = File(...)):
    # Support both admin and customer auth
    user = await get_auth_user(request)
    customer = None if user else await get_customer_user(request)
    if not user and not customer:
        raise HTTPException(401, "请先登录")
    # File restrictions for customers
    if customer and not user:
        ext = Path(file.filename).suffix.lower()
        allowed = {'.doc', '.docx', '.png', '.jpg', '.jpeg', '.gif', '.pdf', '.txt', '.bmp', '.webp'}
        if ext not in allowed:
            raise HTTPException(400, "不支持的文件格式，允许: doc/docx/png/jpg/gif/pdf/txt/bmp/webp")
        content = await file.read()
        if len(content) > 10 * 1024 * 1024:
            raise HTTPException(400, "文件大小不能超过10MB")
        ext = Path(file.filename).suffix or ".bin"
        safe_name = secrets.token_hex(16) + ext
        file_path = UPLOAD_DIR / safe_name
        with open(file_path, "wb") as f: f.write(content)
        return {"url": f"/uploads/{safe_name}", "filename": file.filename, "size": len(content)}
    # Admin uploads - no restrictions
    ext = Path(file.filename).suffix or ".bin"
    safe_name = secrets.token_hex(16) + ext
    file_path = UPLOAD_DIR / safe_name
    content = await file.read()
    with open(file_path, "wb") as f: f.write(content)
    return {"url": f"/uploads/{safe_name}", "filename": file.filename, "size": len(content)}

# ═══════════════════════════════════════════════════
# ADMIN — User Management (existing)
# ═══════════════════════════════════════════════════
@app.get("/api/admin/users")
async def admin_list_users(request: Request):
    await require_admin(request)
    db = await get_db()
    try:
        users = await db_fetchall(db, "SELECT id, username, email, phone, company, role, department, region, created_at FROM users ORDER BY created_at DESC")
        return [dict(u) for u in users]
    finally: await db.close()

@app.post("/api/admin/users")
async def admin_create_user(request: Request, username: str = Form(...), password: str = Form(...),
                            email: str = Form(""), phone: str = Form(""), company: str = Form(""),
                            role: str = Form("user")):
    uname_err = validate_username(username)
    if uname_err: raise HTTPException(400, uname_err)
    pwd_err = validate_password_strength(password)
    if pwd_err: raise HTTPException(400, pwd_err)
    role = safe_str(role, 20)
    if role not in ('user', 'admin', 'partner'): role = 'user'
    await require_admin(request)
    db = await get_db()
    try:
        ph = hashlib.sha256(password.encode()).hexdigest()
        cur = await db.execute(
            "INSERT INTO users(username,password_hash,email,phone,company,role) VALUES(?,?,?,?,?,?)",
            (username, ph, email, phone, company, role))
        await db.commit(); uid = cur.lastrowid
        return {"id": uid}
    except Exception as e:
        if "UNIQUE" in str(e): raise HTTPException(400, "用户名已存在")
        raise HTTPException(500, "创建用户失败")
    finally: await db.close()

@app.put("/api/admin/users/{uid}")
async def admin_update_user(uid: int, request: Request, username: str = Form(""), email: str = Form(""),
                            phone: str = Form(""), company: str = Form(""), role: str = Form(""),
                            department: str = Form(""), region: str = Form("")):
    await require_admin(request)
    db = await get_db()
    try:
        if username:
            uname_err = validate_username(username)
            if uname_err: raise HTTPException(400, uname_err)
            await db.execute("UPDATE users SET username=? WHERE id=?", (safe_str(username, 50), uid))
        if email: await db.execute("UPDATE users SET email=? WHERE id=?", (safe_str(email, 200), uid))
        if phone: await db.execute("UPDATE users SET phone=? WHERE id=?", (safe_str(phone, 30), uid))
        if company: await db.execute("UPDATE users SET company=? WHERE id=?", (safe_str(company, 200), uid))
        if department: await db.execute("UPDATE users SET department=? WHERE id=?", (safe_str(department, 100), uid))
        if region: await db.execute("UPDATE users SET region=? WHERE id=?", (safe_str(region, 50), uid))
        if role:
            r = safe_str(role, 20)
            if r in ('user', 'admin', 'partner'): await db.execute("UPDATE users SET role=? WHERE id=?", (r, uid))
        await db.commit()
        return {"ok": True}
    finally: await db.close()

@app.put("/api/admin/users/{uid}/reset-password")
async def admin_reset_password(uid: int, request: Request, new_password: str = Form(...)):
    pwd_err = validate_password_strength(new_password)
    if pwd_err: raise HTTPException(400, pwd_err)
    await require_admin(request)
    db = await get_db()
    try:
        admin = await get_auth_user(request)
        if uid == admin["id"]: raise HTTPException(400, "不能重置自己的密码")
        ph = hashlib.sha256(new_password.encode()).hexdigest()
        await db.execute("UPDATE users SET password_hash=? WHERE id=?", (ph, uid))
        await db.commit()
        return {"ok": True}
    finally: await db.close()

@app.delete("/api/admin/users/{uid}")
async def admin_delete_user(uid: int, request: Request):
    await require_admin(request)
    db = await get_db()
    try:
        admin = await get_auth_user(request)
        if uid == admin["id"]: raise HTTPException(400, "不能删除自己")
        await db.execute("DELETE FROM users WHERE id=? AND username!='admin'", (uid,))
        await db.commit()
        return {"ok": True}
    finally: await db.close()

# ═══════════════════════════════════════════════════
# ADMIN — Dashboard Stats
# ═══════════════════════════════════════════════════
@app.get("/api/admin/stats")
async def admin_stats(request: Request):
    await require_admin(request)
    db = await get_db()
    try:
        users = (await db_fetchone(db, "SELECT COUNT(*) as c FROM users"))["c"]
        leads = (await db_fetchone(db, "SELECT COUNT(*) as c FROM leads"))["c"]
        partners = (await db_fetchone(db, "SELECT COUNT(*) as c FROM partners"))["c"]
        tickets_open = (await db_fetchone(db, "SELECT COUNT(*) as c FROM tickets WHERE status='open'"))["c"]
        opportunities = (await db_fetchone(db, "SELECT COUNT(*) as c FROM opportunities"))["c"]
        kb_articles = (await db_fetchone(db, "SELECT COUNT(*) as c FROM kb_articles"))["c"]
        qa_open = (await db_fetchone(db, "SELECT COUNT(*) as c FROM qa_questions WHERE status='open'"))["c"]
        training_modules = (await db_fetchone(db, "SELECT COUNT(*) as c FROM training_modules"))["c"]
        customer_users = (await db_fetchone(db, "SELECT COUNT(*) as c FROM customer_users"))["c"]
        return {"users": users, "leads": leads, "partners": partners, "tickets_open": tickets_open,
                "opportunities": opportunities, "kb_articles": kb_articles, "qa_open": qa_open,
                "training_modules": training_modules, "customer_users": customer_users}
    finally: await db.close()

# ═══════════════════════════════════════════════════
# CUSTOMER AUTH APIS
# ═══════════════════════════════════════════════════
@app.post("/api/customer/register")
async def customer_register_admin(username: str = Form(...), password: str = Form(...),
                            email: str = Form(""), phone: str = Form(""),
                            company: str = Form(""), product_purchased: str = Form("")):
    uname_err = validate_username(username)
    if uname_err: raise HTTPException(400, uname_err)
    pwd_err = validate_password_strength(password)
    if pwd_err: raise HTTPException(400, pwd_err)
    username = safe_str(username, 50)
    email = safe_str(email, 200)
    phone = safe_str(phone, 30)
    company = safe_str(company, 200)
    db = await get_db()
    try:
        ph = hashlib.sha256(password.encode()).hexdigest()
        cur = await db.execute(
            "INSERT INTO customer_users(username,password_hash,email,phone,company,product_purchased) VALUES(?,?,?,?,?,?)",
            (username, ph, email, phone, company, safe_str(product_purchased, 200)))
        await db.commit(); uid = cur.lastrowid
        token = secrets.token_hex(32)
        await db.execute("INSERT INTO customer_tokens(customer_id,token) VALUES(?,?)", (uid, token))
        await db.commit()
        return {"token": token, "username": username, "role": "customer", "id": uid}
    except Exception as e:
        if "UNIQUE" in str(e): raise HTTPException(400, "用户名已存在")
        raise HTTPException(500, "注册失败")
    finally: await db.close()

@app.post("/api/customer/login")
async def customer_login(request: Request, username: str = Form(...), password: str = Form(...)):
    client_ip = request.client.host if request.client else "unknown"
    if not check_login_rate(client_ip):
        raise HTTPException(429, "登录尝试过于频繁，请5分钟后再试")
    record_login_attempt(client_ip)
    username = safe_str(username, 50)
    if not username or not password: raise HTTPException(400, "用户名和密码不能为空")
    db = await get_db()
    try:
        ph = hashlib.sha256(password.encode()).hexdigest()
        user = await db_fetchone(db, "SELECT * FROM customer_users WHERE username=? AND password_hash=?", (username, ph))
        if not user: await log_login("internal", username, client_ip, False, "密码错误"); raise HTTPException(400, "用户名或密码错误")
        user = dict(user)
        # Check if frozen
        if user.get("status") == "frozen": raise HTTPException(400, "账号已被冻结，请联系管理员")
        # Check expiration
        if user.get("valid_from") and user.get("valid_days"):
            from datetime import datetime as dt
            try:
                vf = dt.strptime(user["valid_from"][:10], "%Y-%m-%d")
                expire = vf + timedelta(days=int(user["valid_days"]))
                if dt.now() > expire: raise HTTPException(400, "账号已过期，请联系管理员续期")
            except: pass
        token = secrets.token_hex(32)
        await db.execute("INSERT INTO customer_tokens(customer_id,token) VALUES(?,?)", (user["id"], token))
        await db.commit()
        user["token"] = token; user["role"] = "customer"
        await log_login("customer", username, client_ip, True)
        return user
    finally: await db.close()

@app.get("/api/customer/me")
async def customer_me(request: Request):
    user = await get_customer_user(request)
    if not user: return {"username": "guest", "role": "guest"}
    return user

@app.post("/api/customer/forgot-password")
async def customer_forgot_password(username: str = Form(...), email: str = Form(...)):
    username = safe_str(username, 50)
    email = safe_str(email, 200)
    if not username or not email: raise HTTPException(400, "请填写用户名和邮箱")
    db = await get_db()
    try:
        user = await db_fetchone(db, "SELECT * FROM customer_users WHERE username=? AND email=?", (username, email))
        if not user: raise HTTPException(400, "用户名或邮箱不匹配")
        import random, string
        new_pwd = ''.join(random.choices(string.ascii_letters + string.digits, k=10))
        ph = hashlib.sha256(new_pwd.encode()).hexdigest()
        await db.execute("UPDATE customer_users SET password_hash=? WHERE id=?", (ph, user["id"]))
        await db.commit()
        return {"message": "密码已重置，新密码为: " + new_pwd + "。请使用新密码登录后立即修改密码。"}
    finally: await db.close()

# ═══════════════════════════════════════════════════
# CUSTOMER — Admin User Management
# ═══════════════════════════════════════════════════
@app.post("/api/customer/admin/users")
async def customer_admin_create_user(request: Request, username: str = Form(...), password: str = Form(...), email: str = Form(""), phone: str = Form(""), company: str = Form(""), contact_name: str = Form(""), position: str = Form(""), product_purchased: str = Form(""), industry: str = Form(""), valid_from: str = Form(""), valid_days: int = Form(365)):
    await require_admin(request)
    uname_err = validate_username(username)
    if uname_err: raise HTTPException(400, uname_err)
    pwd_err = validate_password_strength(password)
    if pwd_err: raise HTTPException(400, pwd_err)
    db = await get_db()
    try:
        ph = hashlib.sha256(password.encode()).hexdigest()
        cur = await db.execute("INSERT INTO customer_users(username,password_hash,email,phone,company,contact_name,position,product_purchased,industry,valid_from,valid_days) VALUES(?,?,?,?,?,?,?,?,?,?,?)",(safe_str(username,50),ph,safe_str(email,200),safe_str(phone,30),safe_str(company,200),safe_str(contact_name,100),safe_str(position,100),safe_str(product_purchased,200),safe_str(industry,100),safe_str(valid_from,20),valid_days))
        await db.commit(); uid = cur.lastrowid
        return {"id":uid,"ok":True}
    except Exception as e:
        if "UNIQUE" in str(e): raise HTTPException(400, "用户名已存在")
        raise HTTPException(500, "创建失败")
    finally: await db.close()
@app.get("/api/customer/admin/users")
async def customer_admin_list_users(request: Request):
    await require_admin(request)
    db = await get_db()
    try:
        users = await db_fetchall(db, "SELECT id, username, email, phone, company, contact_name, position, product_purchased, industry, valid_from, valid_days, status, created_at FROM customer_users ORDER BY created_at DESC")
        return [dict(u) for u in users]
    finally: await db.close()

@app.put("/api/customer/admin/users/{uid}/reset-password")
async def customer_admin_reset_password(uid: int, request: Request, new_password: str = Form(...)):
    pwd_err = validate_password_strength(new_password)
    if pwd_err: raise HTTPException(400, pwd_err)
    await require_admin(request)
    db = await get_db()
    try:
        ph = hashlib.sha256(new_password.encode()).hexdigest()
        await db.execute("UPDATE customer_users SET password_hash=? WHERE id=?", (ph, uid))
        await db.commit()
        return {"ok": True}
    finally: await db.close()

@app.put("/api/customer/admin/users/{uid}/status")
async def customer_admin_set_status(uid: int, request: Request, status: str = Form(...)):
    await require_admin(request)
    if status not in ("active", "frozen"): raise HTTPException(400, "状态值无效")
    db = await get_db()
    try:
        await db.execute("UPDATE customer_users SET status=? WHERE id=?", (status, uid))
        await db.commit()
        return {"ok": True}
    finally: await db.close()

@app.delete("/api/customer/admin/users/{uid}")
async def customer_admin_delete_user(uid: int, request: Request):
    await require_admin(request)
    db = await get_db()
    await db.execute("DELETE FROM customer_users WHERE id=?", (uid,))
    await db.execute("DELETE FROM customer_tokens WHERE customer_id=?", (uid,))
    await db.commit(); await db.close()
    return {"ok": True}

# ═══════════════════════════════════════════════════
# KNOWLEDGE BASE APIS
# ═══════════════════════════════════════════════════
@app.get("/api/kb/articles")
async def list_kb_articles(category: str = "", product_id: str = "", search: str = "", limit: int = 20):
    db = await get_db()
    try:
        sql = "SELECT id,title,summary,category,tags,product_id,author,view_count,created_at FROM kb_articles WHERE published=1"
        params = []
        if category:
            sql += " AND category=?"; params.append(safe_str(category, 100))
        if product_id:
            sql += " AND product_id=?"; params.append(safe_str(product_id, 50))
        if search:
            sql += " AND (title LIKE ? OR summary LIKE ? OR content LIKE ?)"
            kw = f"%{safe_str(search, 200)}%"; params.extend([kw, kw, kw])
        sql += " ORDER BY created_at DESC LIMIT ?"; params.append(min(limit, 100))
        rows = await db_fetchall(db, sql, tuple(params))
        return [dict(r) for r in rows]
    finally: await db.close()

@app.get("/api/kb/articles/{aid}")
async def get_kb_article(aid: int):
    db = await get_db()
    try:
        row = await db_fetchone(db, "SELECT * FROM kb_articles WHERE id=? AND published=1", (aid,))
        if not row: raise HTTPException(404, "文章不存在")
        await db.execute("UPDATE kb_articles SET view_count=view_count+1 WHERE id=?", (aid,))
        await db.commit()
        return dict(row)
    finally: await db.close()

@app.post("/api/kb/articles")
async def create_kb_article(request: Request, title: str = Form(...), content: str = Form(""),
                             summary: str = Form(""), category: str = Form("产品文档"),
                             tags: str = Form(""), product_id: str = Form(""), author: str = Form("软安科技")):
    await require_admin(request)
    db = await get_db()
    try:
        cur = await db.execute(
            "INSERT INTO kb_articles(title,content,summary,category,tags,product_id,author) VALUES(?,?,?,?,?,?,?)",
            (safe_str(title, 200), safe_str(content, 50000), safe_str(summary, 500),
             safe_str(category, 100), safe_str(tags, 500), safe_str(product_id, 50), safe_str(author, 100)))
        await db.commit(); aid = cur.lastrowid
        return {"id": aid, "ok": True}
    finally: await db.close()

@app.put("/api/kb/articles/{aid}")
async def update_kb_article(aid: int, request: Request, title: str = Form(""), content: str = Form(""),
                             summary: str = Form(""), category: str = Form(""), tags: str = Form(""),
                             product_id: str = Form(""), published: str = Form("")):
    await require_admin(request)
    db = await get_db()
    try:
        if title: await db.execute("UPDATE kb_articles SET title=?,updated_at=datetime('now','localtime') WHERE id=?", (safe_str(title, 200), aid))
        if content: await db.execute("UPDATE kb_articles SET content=?,updated_at=datetime('now','localtime') WHERE id=?", (safe_str(content, 50000), aid))
        if summary: await db.execute("UPDATE kb_articles SET summary=?,updated_at=datetime('now','localtime') WHERE id=?", (safe_str(summary, 500), aid))
        if category: await db.execute("UPDATE kb_articles SET category=?,updated_at=datetime('now','localtime') WHERE id=?", (safe_str(category, 100), aid))
        if tags: await db.execute("UPDATE kb_articles SET tags=?,updated_at=datetime('now','localtime') WHERE id=?", (safe_str(tags, 500), aid))
        if product_id: await db.execute("UPDATE kb_articles SET product_id=?,updated_at=datetime('now','localtime') WHERE id=?", (safe_str(product_id, 50), aid))
        if published: await db.execute("UPDATE kb_articles SET published=?,updated_at=datetime('now','localtime') WHERE id=?", (int(published), aid))
        await db.commit()
        return {"ok": True}
    finally: await db.close()

@app.delete("/api/kb/articles/{aid}")
async def delete_kb_article(aid: int, request: Request):
    await require_admin(request)
    db = await get_db()
    await db.execute("DELETE FROM kb_articles WHERE id=?", (aid,))
    await db.commit(); await db.close()
    return {"ok": True}

# ═══════════════════════════════════════════════════
# Q&A COMMUNITY APIS
# ═══════════════════════════════════════════════════
QUESTION_TAGS = ["产品使用问题", "产品BUG提交", "产品技巧问题", "产品数据问题", "业务流程咨询", "其他"]

@app.post("/api/qa/questions")
async def create_qa_question(request: Request, subject: str = Form(...), description: str = Form(""),
                              category: str = Form("产品使用问题"), tags: str = Form(""),
                              file_urls: str = Form("")):
    await require_customer(request)
    customer = await get_customer_user(request)
    if category not in QUESTION_TAGS:
        category = "产品使用问题"
    db = await get_db()
    try:
        cur = await db.execute(
            "INSERT INTO qa_questions(customer_id,subject,description,category,tags) VALUES(?,?,?,?,?)",
            (customer["id"], safe_str(subject, 200), safe_str(description, 5000),
             safe_str(category, 50), safe_str(tags, 500), safe_str(file_urls, 2000)))
        await db.commit(); qid = cur.lastrowid
        return {"id": qid, "ok": True}
    finally: await db.close()

@app.get("/api/qa/questions")
async def list_qa_questions(category: str = "", status: str = "", search: str = "", limit: int = 20):
    db = await get_db()
    try:
        sql = "SELECT q.*, cu.username as customer_name FROM qa_questions q LEFT JOIN customer_users cu ON q.customer_id=cu.id WHERE 1=1"
        params = []
        if category:
            sql += " AND q.category=?"; params.append(safe_str(category, 50))
        if status:
            sql += " AND q.status=?"; params.append(safe_str(status, 20))
        if search:
            sql += " AND (q.subject LIKE ? OR q.description LIKE ?)"
            kw = f"%{safe_str(search, 200)}%"; params.extend([kw, kw])
        sql += " ORDER BY q.created_at DESC LIMIT ?"; params.append(min(limit, 100))
        rows = await db_fetchall(db, sql, tuple(params))
        return [dict(r) for r in rows]
    finally: await db.close()

@app.get("/api/qa/questions/{qid}")
async def get_qa_question(qid: int):
    db = await get_db()
    try:
        row = await db_fetchone(db, "SELECT q.*, cu.username as customer_name FROM qa_questions q LEFT JOIN customer_users cu ON q.customer_id=cu.id WHERE q.id=?", (qid,))
        if not row: raise HTTPException(404, "问题不存在")
        q = dict(row)
        answers = await db_fetchall(db, "SELECT a.*, CASE WHEN a.is_staff=1 THEN '软安技术支持' ELSE cu.username END as answerer_name FROM qa_answers a LEFT JOIN customer_users cu ON a.answerer_id=cu.id WHERE a.question_id=? ORDER BY a.created_at ASC", (qid,))
        q["answers"] = [dict(a) for a in answers]
        return q
    finally: await db.close()

@app.post("/api/qa/questions/{qid}/answers")
async def answer_qa_question(qid: int, request: Request, content: str = Form(...)):
    user = await get_auth_user(request)
    customer = None if user else await get_customer_user(request)
    if not user and not customer:
        raise HTTPException(401, "请先登录")
    answerer_id = user["id"] if user else customer["id"]
    is_staff = 1 if user else 0
    db = await get_db()
    try:
        cur = await db.execute(
            "INSERT INTO qa_answers(question_id,answerer_id,content,is_staff) VALUES(?,?,?,?)",
            (qid, answerer_id, safe_str(content, 5000), is_staff))
        await db.execute("UPDATE qa_questions SET status='replied' WHERE id=? AND status='open'", (qid,))
        await db.commit()
        return {"id": cur.lastrowid, "ok": True}
    finally: await db.close()

@app.put("/api/qa/questions/{qid}/resolve")
async def resolve_qa_question(qid: int, request: Request):
    await require_admin(request)
    db = await get_db()
    try:
        await db.execute("UPDATE qa_questions SET status='resolved' WHERE id=?", (qid,))
        await db.commit()
        return {"ok": True}
    finally: await db.close()

# ═══════════════════════════════════════════════════
# TRAINING APIS
# ═══════════════════════════════════════════════════
@app.get("/api/training/modules")
async def list_training_modules(product_id: str = "", group_name: str = ""):
    db = await get_db()
    try:
        sql = "SELECT * FROM training_modules WHERE 1=1"
        params = []
        if product_id:
            sql += " AND product_id=?"; params.append(safe_str(product_id, 50))
        if group_name:
            sql += " AND group_name=?"; params.append(safe_str(group_name, 100))
        sql += " ORDER BY sort_order ASC"
        rows = await db_fetchall(db, sql, tuple(params))
        return [dict(r) for r in rows]
    finally: await db.close()

@app.get("/api/training/modules/{mid}")
async def get_training_module(mid: int):
    db = await get_db()
    try:
        row = await db_fetchone(db, "SELECT * FROM training_modules WHERE id=?", (mid,))
        if not row: raise HTTPException(404, "模块不存在")
        return dict(row)
    finally: await db.close()

@app.post("/api/training/modules")
async def create_training_module(request: Request, product_id: str = Form(...), title: str = Form(...),
                                  content: str = Form(""), group_name: str = Form("产品知识"),
                                  sort_order: int = Form(0)):
    await require_admin(request)
    db = await get_db()
    try:
        cur = await db.execute(
            "INSERT INTO training_modules(product_id,title,content,group_name,sort_order) VALUES(?,?,?,?,?)",
            (safe_str(product_id, 50), safe_str(title, 200), safe_str(content, 50000),
             safe_str(group_name, 100), sort_order))
        await db.commit(); mid = cur.lastrowid
        return {"id": mid, "ok": True}
    finally: await db.close()

@app.put("/api/training/modules/{mid}")
async def update_training_module(mid: int, request: Request, title: str = Form(""),
                                  content: str = Form(""), group_name: str = Form(""),
                                  sort_order: str = Form("")):
    await require_admin(request)
    db = await get_db()
    try:
        if title: await db.execute("UPDATE training_modules SET title=? WHERE id=?", (safe_str(title, 200), mid))
        if content: await db.execute("UPDATE training_modules SET content=? WHERE id=?", (safe_str(content, 50000), mid))
        if group_name: await db.execute("UPDATE training_modules SET group_name=? WHERE id=?", (safe_str(group_name, 100), mid))
        if sort_order: await db.execute("UPDATE training_modules SET sort_order=? WHERE id=?", (int(sort_order), mid))
        await db.commit()
        return {"ok": True}
    finally: await db.close()

@app.delete("/api/training/modules/{mid}")
async def delete_training_module(mid: int, request: Request):
    await require_admin(request)
    db = await get_db()
    await db.execute("DELETE FROM training_modules WHERE id=?", (mid,))
    await db.commit(); await db.close()
    return {"ok": True}

@app.get("/api/training/questions")
async def list_training_questions(module_id: int = 0, question_type: str = ""):
    db = await get_db()
    try:
        sql = "SELECT * FROM training_questions WHERE 1=1"
        params = []
        if module_id > 0:
            sql += " AND module_id=?"; params.append(module_id)
        if question_type:
            sql += " AND question_type=?"; params.append(safe_str(question_type, 10))
        sql += " ORDER BY module_id ASC, id ASC"
        rows = await db_fetchall(db, sql, tuple(params))
        return [dict(r) for r in rows]
    finally: await db.close()

@app.post("/api/training/questions")
async def create_training_question(request: Request, module_id: int = Form(0),
                                    question_type: str = Form("mcq"), question_text: str = Form(...),
                                    options: str = Form("[]"), correct_answer: str = Form(""),
                                    explanation: str = Form("")):
    await require_admin(request)
    if question_type not in ("mcq", "essay"): question_type = "mcq"
    db = await get_db()
    try:
        cur = await db.execute(
            "INSERT INTO training_questions(module_id,question_type,question_text,options,correct_answer,explanation) VALUES(?,?,?,?,?,?)",
            (module_id, question_type, safe_str(question_text, 1000), safe_str(options, 2000),
             safe_str(correct_answer, 500), safe_str(explanation, 2000)))
        await db.commit(); qid = cur.lastrowid
        return {"id": qid, "ok": True}
    finally: await db.close()

@app.put("/api/training/questions/{qid}")
async def update_training_question(qid: int, request: Request, module_id: str = Form(""),
                                    question_type: str = Form(""), question_text: str = Form(""),
                                    options: str = Form(""), correct_answer: str = Form(""),
                                    explanation: str = Form("")):
    await require_admin(request)
    db = await get_db()
    try:
        if module_id: await db.execute("UPDATE training_questions SET module_id=? WHERE id=?", (int(module_id), qid))
        if question_type and question_type in ("mcq", "essay"): await db.execute("UPDATE training_questions SET question_type=? WHERE id=?", (question_type, qid))
        if question_text: await db.execute("UPDATE training_questions SET question_text=? WHERE id=?", (safe_str(question_text, 1000), qid))
        if options: await db.execute("UPDATE training_questions SET options=? WHERE id=?", (safe_str(options, 2000), qid))
        if correct_answer: await db.execute("UPDATE training_questions SET correct_answer=? WHERE id=?", (safe_str(correct_answer, 500), qid))
        if explanation: await db.execute("UPDATE training_questions SET explanation=? WHERE id=?", (safe_str(explanation, 2000), qid))
        await db.commit()
        return {"ok": True}
    finally: await db.close()

@app.delete("/api/training/questions/{qid}")
async def delete_training_question(qid: int, request: Request):
    await require_admin(request)
    db = await get_db()
    await db.execute("DELETE FROM training_questions WHERE id=?", (qid,))
    await db.commit(); await db.close()
    return {"ok": True}

@app.post("/api/training/submit-exam")
async def submit_training_exam(request: Request, answers: str = Form("{}")):
    user = await get_auth_user(request)
    if not user: raise HTTPException(401, "请先登录")
    db = await get_db()
    try:
        import json
        ans = json.loads(answers) if answers else {}
        score = 0; total = 0
        for qid_str, selected in ans.items():
            q = await db_fetchone(db, "SELECT * FROM training_questions WHERE id=? AND question_type='mcq'", (int(qid_str),))
            if q:
                total += 1
                if str(selected) == str(q["correct_answer"]): score += 1
        cur = await db.execute(
            "INSERT INTO training_exam_records(user_id,score,total,answers) VALUES(?,?,?,?)",
            (user["id"], score, total, answers))
        await db.commit()
        pct = round(score * 100 / total) if total > 0 else 0
        grade = "优秀" if pct >= 80 else ("合格" if pct >= 60 else "需加强")
        return {"score": score, "total": total, "percentage": pct, "grade": grade, "id": cur.lastrowid}
    finally: await db.close()

@app.get("/api/training/my-records")
async def my_training_records(request: Request):
    user = await get_auth_user(request)
    if not user: raise HTTPException(401, "请先登录")
    db = await get_db()
    try:
        rows = await db_fetchall(db, "SELECT * FROM training_exam_records WHERE user_id=? ORDER BY created_at DESC LIMIT 20", (user["id"],))
        return [dict(r) for r in rows]
    finally: await db.close()

@app.get("/api/training/admin-records")
async def admin_training_records(request: Request):
    await require_admin(request)
    db = await get_db()
    try:
        rows = await db_fetchall(db, "SELECT r.*, u.username FROM training_exam_records r LEFT JOIN users u ON r.user_id=u.id ORDER BY r.created_at DESC LIMIT 100")
        return [dict(r) for r in rows]
    finally: await db.close()

# ═══════════════════════════════════════════════════
# CUSTOMER PORTAL ROUTE
# ═══════════════════════════════════════════════════

@app.get("/api/admin/audit-logs")
async def admin_audit_logs(request: Request, limit: int = 100):
    await require_admin(request)
    db = await get_db()
    try:
        rows = await db_fetchall(db, "SELECT * FROM login_logs ORDER BY created_at DESC LIMIT ?", (min(limit, 500),))
        return [dict(r) for r in rows]
    finally: await db.close()

@app.get("/api/product-pages")
async def list_product_pages():
    db = await get_db()
    try:
        rows = await db_fetchall(db, "SELECT * FROM product_pages ORDER BY product_id")
        return [dict(r) for r in rows]
    finally: await db.close()

@app.get("/api/product-pages/{pid}")
async def get_product_page(pid: str):
    db = await get_db()
    try:
        row = await db_fetchone(db, "SELECT * FROM product_pages WHERE product_id=?", (safe_str(pid,50),))
        return dict(row) if row else {"product_id":pid,"intro":"","detail":""}
    finally: await db.close()

@app.post("/api/product-pages")
async def save_product_page(request: Request, product_id: str = Form(...), intro: str = Form(""), detail: str = Form("")):
    await require_admin(request)
    db = await get_db()
    try:
        await db.execute("INSERT OR REPLACE INTO product_pages(product_id,intro,detail,updated_at) VALUES(?,?,?,datetime('now','localtime'))",(safe_str(product_id,50),safe_str(intro,5000),safe_str(detail,20000)))
        await db.commit()
        return {"ok":True}
    finally: await db.close()

@app.post("/api/change-password")
async def change_password(request: Request, old_password: str = Form(...), new_password: str = Form(...)):
    user = await get_auth_user(request)
    if not user: raise HTTPException(401, "请先登录")
    pwd_err = validate_password_strength(new_password)
    if pwd_err: raise HTTPException(400, pwd_err)
    db = await get_db()
    try:
        old_ph = hashlib.sha256(old_password.encode()).hexdigest()
        if old_ph != user["password_hash"]: raise HTTPException(400, "原密码错误")
        new_ph = hashlib.sha256(new_password.encode()).hexdigest()
        await db.execute("UPDATE users SET password_hash=? WHERE id=?", (new_ph, user["id"]))
        await db.commit()
        return {"ok": True, "message": "密码修改成功"}
    finally: await db.close()

@app.post("/api/customer/change-password")
async def customer_change_password(request: Request, old_password: str = Form(...), new_password: str = Form(...)):
    user = await get_customer_user(request)
    if not user: raise HTTPException(401, "请先登录")
    pwd_err = validate_password_strength(new_password)
    if pwd_err: raise HTTPException(400, pwd_err)
    db = await get_db()
    try:
        old_ph = hashlib.sha256(old_password.encode()).hexdigest()
        if old_ph != user["password_hash"]: raise HTTPException(400, "原密码错误")
        new_ph = hashlib.sha256(new_password.encode()).hexdigest()
        await db.execute("UPDATE customer_users SET password_hash=? WHERE id=?", (new_ph, user["id"]))
        await db.commit()
        return {"ok": True, "message": "密码修改成功"}
    finally: await db.close()

# ═══════════════════════════════════════════════════
# ROUTES
# ═══════════════════════════════════════════════════
@app.get("/selector")
async def selector(): return FileResponse(str(STATIC_FILE))

@app.get("/support")
async def customer_portal(): return FileResponse(str(CUSTOMER_PORTAL_FILE))

@app.get("/partner")
async def partner_portal(): return FileResponse(str(PARTNER_FILE))

@app.get("/")
async def index(): return FileResponse(str(MARKETING_FILE))

# Static HTML files (also served by filename for GitHub Pages compatibility)
@app.get("/ruanan-product-selector.html")
async def selector_file(): return FileResponse(str(STATIC_FILE))

@app.get("/ruanan-partner-portal.html")
async def partner_file(): return FileResponse(str(PARTNER_FILE))

@app.get("/ruanan-customer-portal.html")
async def customer_file(): return FileResponse(str(CUSTOMER_PORTAL_FILE))

@app.get("/ruanan-marketing-platform.html")
async def marketing_file(): return FileResponse(str(MARKETING_FILE))

@app.get("/promo_video.html")
async def promo_video_file(): return FileResponse(str(PROMO_VIDEO_FILE))

@app.get("/outro.html")
async def outro_file(): return FileResponse(str(OUTRO_FILE))

@app.on_event("startup")
async def startup():
    await init_db()
    print("=" * 60)
    print("  软安科技华南营销管理平台 API v3.0")
    print("  Address: http://localhost:8081")
    if not os.environ.get("ADMIN_PWD"):
        print(f"  Admin account: admin")
        print(f"  Admin password: {ADMIN_PWD}")
        print("  [!] Save this password! Set ADMIN_PWD env var to override.")
    print("=" * 60)

if __name__ == "__main__":
    import uvicorn; uvicorn.run(app, host="0.0.0.0", port=8081, log_level="info")
