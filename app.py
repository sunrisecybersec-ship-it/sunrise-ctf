import os, json, sqlite3, secrets, hashlib, hmac, time, csv, io, re
from urllib.parse import quote
from contextlib import contextmanager
from datetime import datetime, timezone, timedelta
from functools import wraps
from pathlib import Path
from flask import Flask, request, jsonify, session, render_template_string, redirect, make_response, url_for

# Set LEVEL=both in Render to serve both exams from one website and admin panel.
LEVEL = os.environ.get("LEVEL", "both").lower()
if LEVEL not in ("level1", "level2", "both"):
    raise RuntimeError("LEVEL must be level1, level2, or both")
PORT = int(os.environ.get("PORT", "8000"))
DB_PATH = os.environ.get("DB_PATH", "/data/exam.db")
SECRET_KEY = os.environ.get("SECRET_KEY")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD")
DURATION_MINUTES = int(os.environ.get("DURATION_MINUTES", "60"))
LEVEL_DURATIONS = {"level1": int(os.environ.get("LEVEL1_DURATION_MINUTES", "60")), "level2": int(os.environ.get("LEVEL2_DURATION_MINUTES", "120"))}
if not SECRET_KEY or not ADMIN_PASSWORD:
    raise RuntimeError("SECRET_KEY and ADMIN_PASSWORD are required. Run python setup.py first.")
os.makedirs(os.path.dirname(DB_PATH) or ".", exist_ok=True)

app = Flask(__name__)
app.secret_key = SECRET_KEY
app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax",
                  SESSION_COOKIE_SECURE=os.environ.get("COOKIE_SECURE", "0") == "1",
                  MAX_CONTENT_LENGTH=64 * 1024, PERMANENT_SESSION_LIFETIME=timedelta(hours=5))

LEVEL_TITLES = {"level1":"Level 1 — Ethical Hacking", "level2":"Level 2 — Penetration Testing"}
VALID_TYPES = {"flag", "short_text", "single_choice", "multiple_choice", "true_false"}
ROLE_PERMISSIONS = {
    "super_admin": {"manage_users", "manage_students", "manage_questions", "view_results", "manage_exams", "view_answer_key"},
    "exam_admin": {"manage_students", "manage_questions", "view_results", "manage_exams", "view_answer_key"},
    "instructor": {"view_results"},
}
ROLE_LABELS = {"super_admin": "Super Admin", "exam_admin": "Exam Admin", "instructor": "Instructor", "student": "Student"}

def utcnow(): return datetime.now(timezone.utc)
def iso(dt): return dt.isoformat(timespec="seconds")

def password_hash(password,salt_hex):
    return hashlib.pbkdf2_hmac("sha256",password.encode(),bytes.fromhex(salt_hex),310_000).hex()

@contextmanager
def db():
    con=sqlite3.connect(DB_PATH, timeout=20)
    con.row_factory=sqlite3.Row
    con.execute("PRAGMA foreign_keys=ON")
    con.execute("PRAGMA busy_timeout=20000")
    try:
        yield con; con.commit()
    except Exception:
        con.rollback(); raise
    finally: con.close()

def init_db():
    with db() as con:
        con.executescript('''
        CREATE TABLE IF NOT EXISTS candidates(candidate_id TEXT PRIMARY KEY,name TEXT NOT NULL,pin_salt TEXT NOT NULL,pin_hash TEXT NOT NULL,created_at TEXT NOT NULL,active INTEGER NOT NULL DEFAULT 1 CHECK(active IN (0,1)),allowed_levels TEXT NOT NULL DEFAULT 'level1,level2');
        CREATE TABLE IF NOT EXISTS staff_users(id INTEGER PRIMARY KEY AUTOINCREMENT,username TEXT NOT NULL UNIQUE,full_name TEXT NOT NULL,role TEXT NOT NULL CHECK(role IN ('super_admin','exam_admin','instructor')),password_salt TEXT NOT NULL,password_hash TEXT NOT NULL,active INTEGER NOT NULL DEFAULT 1 CHECK(active IN (0,1)),created_at TEXT NOT NULL,updated_at TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS audit_log(id INTEGER PRIMARY KEY AUTOINCREMENT,actor_username TEXT NOT NULL,action TEXT NOT NULL,target TEXT NOT NULL,details TEXT NOT NULL,created_at TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS exam_sessions(candidate_id TEXT NOT NULL,level TEXT NOT NULL,started_at TEXT NOT NULL,deadline_at TEXT NOT NULL,PRIMARY KEY(candidate_id,level),FOREIGN KEY(candidate_id) REFERENCES candidates(candidate_id));
        CREATE TABLE IF NOT EXISTS questions(
          id INTEGER PRIMARY KEY AUTOINCREMENT, level TEXT NOT NULL CHECK(level IN ('level1','level2')),
          title TEXT NOT NULL, prompt TEXT NOT NULL, category TEXT NOT NULL DEFAULT 'General',
          qtype TEXT NOT NULL CHECK(qtype IN ('flag','short_text','single_choice','multiple_choice','true_false')),
          options_json TEXT NOT NULL DEFAULT '[]', answer_json TEXT NOT NULL,
          points INTEGER NOT NULL DEFAULT 100 CHECK(points BETWEEN 1 AND 10000),
          active INTEGER NOT NULL DEFAULT 1 CHECK(active IN (0,1)), created_at TEXT NOT NULL, updated_at TEXT NOT NULL);
        CREATE INDEX IF NOT EXISTS idx_questions_level_active ON questions(level,active,id);
        CREATE TABLE IF NOT EXISTS solves(candidate_id TEXT NOT NULL,level TEXT NOT NULL,challenge_id INTEGER NOT NULL,points INTEGER NOT NULL,solved_at TEXT NOT NULL,PRIMARY KEY(candidate_id,level,challenge_id),FOREIGN KEY(candidate_id) REFERENCES candidates(candidate_id));
        CREATE TABLE IF NOT EXISTS submissions(id INTEGER PRIMARY KEY AUTOINCREMENT,candidate_id TEXT NOT NULL,level TEXT NOT NULL,challenge_id INTEGER NOT NULL,correct INTEGER NOT NULL,submitted_at TEXT NOT NULL,FOREIGN KEY(candidate_id) REFERENCES candidates(candidate_id));
        CREATE INDEX IF NOT EXISTS idx_submissions_rate ON submissions(candidate_id,level,submitted_at);
        CREATE TABLE IF NOT EXISTS exam_answers(candidate_id TEXT NOT NULL, level TEXT NOT NULL, question_id INTEGER NOT NULL, answer_json TEXT NOT NULL, updated_at TEXT NOT NULL, PRIMARY KEY(candidate_id,level,question_id), FOREIGN KEY(candidate_id) REFERENCES candidates(candidate_id));
        CREATE TABLE IF NOT EXISTS exam_results(candidate_id TEXT NOT NULL, level TEXT NOT NULL, score INTEGER NOT NULL, max_score INTEGER NOT NULL, percentage REAL NOT NULL, passed INTEGER NOT NULL, submitted_at TEXT NOT NULL, PRIMARY KEY(candidate_id,level), FOREIGN KEY(candidate_id) REFERENCES candidates(candidate_id));
        ''')
        # Migrate databases created by earlier versions.
        cols={r["name"] for r in con.execute("PRAGMA table_info(candidates)").fetchall()}
        if "active" not in cols:
            con.execute("ALTER TABLE candidates ADD COLUMN active INTEGER NOT NULL DEFAULT 1")
        if "allowed_levels" not in cols:
            # Existing candidates retain access to both levels during migration.
            con.execute("ALTER TABLE candidates ADD COLUMN allowed_levels TEXT NOT NULL DEFAULT 'level1,level2'")
        if con.execute("SELECT COUNT(*) n FROM staff_users").fetchone()["n"] == 0:
            salt=secrets.token_hex(16)
            con.execute("INSERT INTO staff_users(username,full_name,role,password_salt,password_hash,active,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?)",
                ("admin","System Administrator","super_admin",salt,password_hash(ADMIN_PASSWORD,salt),1,iso(utcnow()),iso(utcnow())))
        # Seed each level only when that level has no questions. This makes restarts safe.
        for level in ("level1","level2"):
            count=con.execute("SELECT COUNT(*) n FROM questions WHERE level=?",(level,)).fetchone()["n"]
            if count == 0:
                p=os.path.join(os.path.dirname(__file__),f"challenges_{level}.json")
                with open(p,encoding="utf-8") as f: data=json.load(f)
                now=iso(utcnow())
                for item in data:
                    con.execute("INSERT INTO questions(id,level,title,prompt,category,qtype,options_json,answer_json,points,active,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                        (int(item["id"]) if level=="level1" else int(item["id"])+1000,level,item["title"],item["prompt"],item.get("category","General"),"flag","[]",json.dumps(item["flag"]),int(item.get("points",100)),1,now,now))
init_db()

def active_level():
    selected = session.get("exam_level")
    if selected in ("level1", "level2") and (LEVEL == "both" or selected == LEVEL):
        return selected
    return LEVEL if LEVEL in ("level1", "level2") else None

def allowed_levels_for(candidate_id):
    with db() as con:
        row = con.execute("SELECT allowed_levels FROM candidates WHERE candidate_id=?", (candidate_id,)).fetchone()
    return [x for x in (row["allowed_levels"] or "").split(",") if x in ("level1", "level2")] if row else []

def csrf_token():
    if "csrf" not in session: session["csrf"]=secrets.token_urlsafe(24)
    return session["csrf"]
def check_csrf(sent=None):
    sent = sent if sent is not None else request.headers.get("X-CSRF-Token", "")
    return bool(sent and hmac.compare_digest(sent,session.get("csrf","")))
def student_required(fn):
    @wraps(fn)
    def wrapped(*a,**kw):
        cid=session.get("candidate_id")
        if not cid: return jsonify({"error":"Please sign in again."}),401
        with db() as con: active=con.execute("SELECT active,allowed_levels FROM candidates WHERE candidate_id=?",(cid,)).fetchone()
        if not active or not active["active"]:
            session.clear(); return jsonify({"error":"This student account is disabled. Contact the exam administrator."}),401
        lev = active_level()
        if not lev:
            return jsonify({"error":"Choose an exam level first."}), 409
        if lev not in (active["allowed_levels"] or "").split(","):
            return jsonify({"error":"Your account is not assigned to this exam level. Contact the exam administrator."}),403
        with db() as con:
            final = con.execute("SELECT 1 FROM exam_results WHERE candidate_id=? AND level=?", (cid, lev)).fetchone()
        request.exam_finalized = bool(final)
        return fn(*a,**kw)
    return wrapped
def permission_required(permission=None):
    def decorator(fn):
        @wraps(fn)
        def wrapped(*a,**kw):
            uid=session.get("staff_user_id")
            if not uid: return redirect("/admin/login")
            with db() as con: user=con.execute("SELECT id,username,full_name,role,active FROM staff_users WHERE id=?",(uid,)).fetchone()
            if not user or not user["active"]:
                session.clear(); return redirect("/admin/login")
            if permission and permission not in ROLE_PERMISSIONS.get(user["role"],set()):
                return make_response("Forbidden: your role does not have permission for this action.",403)
            return fn(*a,**kw)
        return wrapped
    return decorator

def admin_required(fn):
    return permission_required()(fn)

def current_staff():
    uid=session.get("staff_user_id")
    if not uid: return None
    with db() as con:
        r=con.execute("SELECT id,username,full_name,role,active FROM staff_users WHERE id=?",(uid,)).fetchone()
        return dict(r) if r else None

def audit(action,target,details=""):
    actor=current_staff()
    if not actor: return
    with db() as con:
        con.execute("INSERT INTO audit_log(actor_username,action,target,details,created_at) VALUES(?,?,?,?,?)",(actor["username"],action,str(target)[:160],str(details)[:1000],iso(utcnow())))

def pin_hash(pin,salt_hex): return hashlib.pbkdf2_hmac("sha256",pin.encode(),bytes.fromhex(salt_hex),240_000).hex()
def candidate_info(cid):
    with db() as con: return con.execute("SELECT candidate_id,name FROM candidates WHERE candidate_id=?",(cid,)).fetchone()
def get_questions(level, active_only=True):
    with db() as con:
        q="SELECT * FROM questions WHERE level=?"+(" AND active=1" if active_only else "")+" ORDER BY id"
        rows=con.execute(q,(level,)).fetchall()
        return [dict(r) for r in rows]
def get_question(qid, level=None, active_only=True):
    level = level or active_level()
    with db() as con:
        q="SELECT * FROM questions WHERE id=? AND level=?"+(" AND active=1" if active_only else "")
        r=con.execute(q,(qid,level)).fetchone()
        return dict(r) if r else None
def public_question(q, solved=False):
    return {"id":q["id"],"title":q["title"],"prompt":q["prompt"],"category":q["category"],"qtype":q["qtype"],
            "options":json.loads(q["options_json"] or "[]"),"points":q["points"],"solved":solved}
def exam_status(cid, start=False, level=None):
    level = level or active_level()
    if level not in ("level1", "level2"):
        return {"started": False, "expired": False, "remaining_seconds": 0, "deadline_at": None}
    now = utcnow()
    with db() as con:
        row = con.execute("SELECT started_at,deadline_at FROM exam_sessions WHERE candidate_id=? AND level=?", (cid, level)).fetchone()
        if row is None and start:
            deadline = now + timedelta(minutes=LEVEL_DURATIONS[level])
            con.execute("INSERT OR IGNORE INTO exam_sessions(candidate_id,level,started_at,deadline_at) VALUES(?,?,?,?)", (cid, level, iso(now), iso(deadline)))
            row = con.execute("SELECT started_at,deadline_at FROM exam_sessions WHERE candidate_id=? AND level=?", (cid, level)).fetchone()
    if row is None:
        return {"started": False, "expired": False, "remaining_seconds": LEVEL_DURATIONS[level]*60, "deadline_at": None}
    deadline = datetime.fromisoformat(row["deadline_at"])
    remaining = max(0, int((deadline-now).total_seconds()))
    return {"started": True, "expired": remaining <= 0, "remaining_seconds": remaining, "deadline_at": row["deadline_at"]}

def validate_question_form(data, existing=None):
    level=(existing["level"] if existing else str(data.get("level","level1")))
    title=str(data.get("title","")).strip(); prompt=str(data.get("prompt","")).strip(); category=str(data.get("category","General")).strip() or "General"
    qtype=str(data.get("qtype","flag")); points_raw=str(data.get("points","100")); active=1 if data.get("active") in ("on","1",1,True) else 0
    if level not in ("level1","level2"): raise ValueError("Select a valid level.")
    if not title or len(title)>160: raise ValueError("Title is required and must be 160 characters or fewer.")
    if not prompt or len(prompt)>12000: raise ValueError("Prompt is required and must be 12,000 characters or fewer.")
    if len(category)>100: raise ValueError("Category must be 100 characters or fewer.")
    if qtype not in VALID_TYPES: raise ValueError("Select a supported question type.")
    try: points=int(points_raw)
    except ValueError: raise ValueError("Points must be a whole number.")
    if not 1<=points<=10000: raise ValueError("Points must be between 1 and 10,000.")
    options=[]
    raw_options=str(data.get("options_json","[]")).strip() or "[]"
    try: options=json.loads(raw_options)
    except json.JSONDecodeError: raise ValueError("Options must be valid JSON.")
    if qtype in ("single_choice","multiple_choice"):
        if not isinstance(options,list) or len(options)<2 or len(options)>50: raise ValueError("MCQ options must be a list with 2–50 options.")
        vals=[]; normalized=[]
        for opt in options:
            if not isinstance(opt,dict) or not str(opt.get("value","")).strip() or not str(opt.get("label","")).strip(): raise ValueError('Each option needs non-empty "value" and "label" fields.')
            value=str(opt["value"]).strip(); label=str(opt["label"]).strip()
            if len(value)>40 or len(label)>500: raise ValueError("Option value/label is too long.")
            vals.append(value); normalized.append({"value":value,"label":label})
        options=normalized
        if len(set(vals))!=len(vals): raise ValueError("Option values must be unique.")
    else: options=[]
    raw_answer=str(data.get("answer","" )).strip()
    if qtype=="flag":
        if not raw_answer or len(raw_answer)>500: raise ValueError("Enter the expected flag answer.")
        answer=raw_answer
    elif qtype=="short_text":
        accepted=[x.strip() for x in raw_answer.splitlines() if x.strip()]
        if not accepted or any(len(x)>500 for x in accepted): raise ValueError("Enter one or more accepted text answers, one per line.")
        answer=accepted
    elif qtype=="single_choice":
        if raw_answer not in [x["value"].strip() for x in options]: raise ValueError("Correct answer must match one option value exactly.")
        answer=raw_answer
    elif qtype=="multiple_choice":
        answers=list(dict.fromkeys(x.strip() for x in raw_answer.split(",") if x.strip()))
        vals=[x["value"].strip() for x in options]
        if len(answers)<2 or not set(answers).issubset(set(vals)): raise ValueError("For multiple choice, enter at least two valid option values separated by commas, e.g. A,C.")
        answer=answers
    else:
        if raw_answer.lower() not in ("true","false"): raise ValueError("True/False answer must be true or false.")
        answer=raw_answer.lower(); options=[{"value":"true","label":"True"},{"value":"false","label":"False"}]
    return {"level":level,"title":title,"prompt":prompt,"category":category,"qtype":qtype,"options_json":json.dumps(options,ensure_ascii=False),"answer_json":json.dumps(answer,ensure_ascii=False),"points":points,"active":active}

def answers_match(q, submitted):
    qtype=q["qtype"]
    try: expected=json.loads(q["answer_json"])
    except Exception: return False
    if qtype in ("flag","short_text"):
        if isinstance(submitted,list): return False
        given=str(submitted or "").strip()
        accepted=expected if isinstance(expected,list) else [expected]
        return any(hmac.compare_digest(given.casefold(),str(x).strip().casefold()) for x in accepted)
    if qtype=="single_choice":
        if isinstance(submitted,list): return False
        return hmac.compare_digest(str(submitted or "").strip(),str(expected))
    if qtype=="multiple_choice":
        if not isinstance(submitted,list): return False
        return set(map(str,submitted))==set(map(str,expected))
    if qtype=="true_false":
        if isinstance(submitted,list): return False
        return str(submitted or "").lower() == str(expected).lower()
    return False

@app.after_request
def security_headers(resp):
    resp.headers["X-Content-Type-Options"]="nosniff"; resp.headers["X-Frame-Options"]="DENY"; resp.headers["Referrer-Policy"]="no-referrer"
    resp.headers["Permissions-Policy"]="camera=(), microphone=(), geolocation=()"; resp.headers["Cache-Control"]="no-store"
    return resp

LOGIN_HTML=r'''<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Sunrise CTF Sign in</title><style>body{margin:0;background:#0b1220;color:#e8eef8;font:16px system-ui;min-height:100vh;display:grid;place-items:center;padding:20px}.card{width:min(100%,460px);background:#111c30;border:1px solid #263750;border-radius:16px;padding:26px}input{width:100%;box-sizing:border-box;padding:12px;margin:8px 0;background:#09111f;color:#fff;border:1px solid #354965;border-radius:9px}button{width:100%;padding:12px;margin-top:12px;background:#58d5b3;border:0;border-radius:9px;font-weight:bold}.muted{color:#9aaec8;font-size:14px}.error{color:#fecdd3}</style></head><body><section class="card"><h1>Sunrise Cybersecurity CTF</h1><p class="muted">{{level_title}} · Candidate sign in</p><form id="login"><label>Candidate ID</label><input id="cid" autocomplete="username" required maxlength="80"><label>PIN</label><input id="pin" type="password" autocomplete="current-password" required maxlength="80"><button>Sign in</button></form><p id="msg" class="error"></p><p class="muted"><a href="/admin/login">Instructor sign in</a></p></section><script>const csrf={{csrf|tojson}};document.getElementById('login').onsubmit=async e=>{e.preventDefault();const r=await fetch('/api/login',{method:'POST',headers:{'Content-Type':'application/json','X-CSRF-Token':csrf},body:JSON.stringify({candidate_id:document.getElementById('cid').value.trim(),pin:document.getElementById('pin').value})});const d=await r.json();if(r.ok)location.href='/';else document.getElementById('msg').textContent=d.error||'Sign in failed.';};</script></body></html>'''

EXAM_HTML=r'''<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Sunrise CTF Exam</title><style>
:root{--bg:#0b1220;--panel:#111c30;--line:#263750;--text:#e8eef8;--muted:#9aaec8;--accent:#58d5b3}*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font:16px/1.5 system-ui,Arial}header{padding:20px max(18px,calc((100vw - 1180px)/2));border-bottom:1px solid var(--line);display:flex;justify-content:space-between;gap:12px;align-items:center;flex-wrap:wrap}h1{margin:0;font-size:clamp(20px,3vw,29px)}header p,.muted{color:var(--muted);font-size:14px}.actions{display:flex;gap:8px;flex-wrap:wrap}button{cursor:pointer}.pill{border:1px solid var(--line);border-radius:99px;padding:7px 11px;font-size:13px}main{max-width:1180px;margin:22px auto;padding:0 16px;display:grid;grid-template-columns:290px 1fr;gap:16px}.panel,.challenge{background:var(--panel);border:1px solid var(--line);border-radius:14px;padding:18px;min-width:0}.stat{font-size:25px;font-weight:750}.progress{height:8px;background:#24334b;border-radius:20px;overflow:hidden;margin:8px 0 16px}.bar{height:100%;background:var(--accent);width:0}nav{display:grid;grid-template-columns:repeat(5,1fr);gap:6px;margin-top:14px}nav button{padding:9px;border:1px solid var(--line);background:#17253b;color:var(--text);border-radius:8px}nav button.done{background:#145b42;border-color:#22a879}nav button.active{outline:2px solid var(--accent)}.tag{display:inline-block;background:#203657;color:#b8d5ff;padding:4px 9px;border-radius:20px;font-size:12px}.prompt{white-space:pre-wrap;overflow-wrap:anywhere;line-height:1.65;margin:18px 0}.answer-option{display:flex;gap:10px;align-items:flex-start;border:1px solid var(--line);border-radius:9px;padding:12px;margin:8px 0}.answer-option input{margin-top:5px}.answer-text{width:100%;padding:12px;border:1px solid #354965;border-radius:9px;background:#09111f;color:#fff;font:inherit}.action{padding:10px 14px;border:0;border-radius:9px;background:var(--accent);color:#08231c;font-weight:750}.secondary{background:#243650;color:var(--text)}.feedback{margin-top:12px;padding:11px;border-radius:9px;background:#17253b;color:#c8d5e8}.notice{padding:10px;border:1px solid #725b28;background:#3d321a;color:#f9e7a5;border-radius:9px;font-size:13px;margin-top:14px}footer{max-width:1180px;margin:auto;padding:0 16px 24px;color:var(--muted);font-size:12px}.final{width:min(100%,520px);margin:24px auto;padding:26px;background:var(--panel);border:1px solid var(--line);border-radius:16px;text-align:center}.hidden{display:none!important}@media(max-width:800px){main{grid-template-columns:1fr}nav{grid-template-columns:repeat(6,1fr)}}
</style></head><body><header><div><h1>Sunrise Cybersecurity CTF</h1><p>{{level_title}}</p></div><div class="actions"><span class="pill">{{candidate_name}} · {{candidate_id}}</span><span class="pill">Time left: <b id="timer">Loading…</b></span><button class="action secondary" id="logout">Sign out</button></div></header><main id="examMain"><aside class="panel"><div class="muted">QUESTIONS ANSWERED</div><div class="stat"><span id="answered">0</span> / <span id="total">0</span></div><div class="progress"><div class="bar" id="bar"></div></div><p class="muted">Save each answer as you go. No answer feedback is shown during the exam. Your score and pass/fail result appear only after final submission.</p><nav id="nav"></nav><div class="notice">Passing score: 70%. Review your answers before final submission.</div><button class="action" id="finish" type="button" style="width:100%;margin-top:14px">Submit completed exam</button></aside><section class="challenge"><div class="tag" id="category">Question</div><h2 id="title">Loading question…</h2><div class="muted" id="meta"></div><div class="prompt" id="prompt"></div><form id="answerForm"><div id="answerArea"></div><div class="actions" style="margin-top:14px"><button class="action" id="saveBtn" type="submit">Save answer</button><button class="action secondary" id="clear" type="button">Clear answer</button><button class="action secondary" id="next" type="button">Next question →</button></div></form><div id="feedback" class="feedback" role="status" aria-live="polite">Your answer has not been saved yet.</div><div id="expired" class="notice hidden">Time is up. Submit the exam to receive your result.</div></section></main><section id="result" class="final hidden"></section><footer>Answers are recorded privately. The final score and pass/fail result are shown after the exam is submitted.</footer>
<script>
const csrf={{csrf|tojson}};let questions=[],current=null,answeredSet=new Set(),deadline=null,timerHandle=null,expired=false,finalized=false;
const nav=document.getElementById('nav');async function api(url,opts={}){opts.headers=Object.assign({'X-CSRF-Token':csrf},opts.headers||{});return fetch(url,opts)}
function message(msg){document.getElementById('feedback').textContent=msg}
function stats(){document.getElementById('answered').textContent=answeredSet.size;document.getElementById('bar').style.width=(questions.length?answeredSet.size/questions.length*100:0)+'%';document.querySelectorAll('nav button').forEach(b=>b.classList.toggle('done',answeredSet.has(Number(b.dataset.id))))}
function renderTimer(){if(!deadline||finalized)return;let n=Math.max(0,Math.floor((deadline-Date.now())/1000));document.getElementById('timer').textContent=[Math.floor(n/3600),Math.floor(n%3600/60),n%60].map(x=>String(x).padStart(2,'0')).join(':');if(n<=0){expired=true;document.getElementById('expired').classList.remove('hidden');document.querySelectorAll('#answerArea input,#saveBtn,#clear,#next').forEach(x=>x.disabled=true);clearInterval(timerHandle)}}
function renderAnswer(q){const area=document.getElementById('answerArea');area.replaceChildren();const saved=q.saved_answer;if(q.qtype==='single_choice'||q.qtype==='true_false'){(q.options||[]).forEach(o=>{const label=document.createElement('label');label.className='answer-option';const input=document.createElement('input');input.type='radio';input.name='answer';input.value=o.value;input.required=true;input.checked=saved===o.value;const span=document.createElement('span');span.textContent=o.label;label.append(input,span);area.append(label)})}else if(q.qtype==='multiple_choice'){(q.options||[]).forEach(o=>{const label=document.createElement('label');label.className='answer-option';const input=document.createElement('input');input.type='checkbox';input.name='answer';input.value=o.value;input.checked=Array.isArray(saved)&&saved.includes(o.value);const span=document.createElement('span');span.textContent=o.label;label.append(input,span);area.append(label)})}else{const label=document.createElement('label');label.textContent=q.qtype==='flag'?'Flag answer':'Text answer';label.htmlFor='answerText';const input=document.createElement('input');input.className='answer-text';input.id='answerText';input.name='answer';input.autocomplete='off';input.spellcheck=false;input.maxLength=500;input.required=true;input.value=typeof saved==='string'?saved:'';input.placeholder=q.qtype==='flag'?'Enter your flag':'Enter your answer';area.append(label,input)}if(finalized||expired)area.querySelectorAll('input').forEach(x=>x.disabled=true)}
async function load(id){if(finalized)return;current=questions.find(q=>q.id===id);if(!current)return;const r=await api('/api/challenge/'+id);if(r.status===401){location.reload();return}const q=await r.json();if(!r.ok){message(q.error||'Could not load question.');return}document.getElementById('title').textContent=q.title;document.getElementById('category').textContent=q.category;document.getElementById('meta').textContent='Question '+(questions.findIndex(x=>x.id===id)+1)+' of '+questions.length+' · '+q.points+' points';document.getElementById('prompt').textContent=q.prompt;renderAnswer(q);document.querySelectorAll('nav button').forEach(b=>b.classList.toggle('active',Number(b.dataset.id)===id));message(answeredSet.has(id)?'Saved. You may change this answer before final submission.':'Select or enter an answer, then click Save answer.')}
async function init(){const r=await api('/api/challenges');if(!r.ok){location.reload();return}const d=await r.json();questions=d.questions;answeredSet=new Set(d.answered||[]);deadline=d.deadline_at?Date.parse(d.deadline_at):null;expired=d.expired;finalized=d.finalized;document.getElementById('total').textContent=questions.length;nav.replaceChildren();questions.forEach((q,i)=>{const b=document.createElement('button');b.type='button';b.textContent=i+1;b.dataset.id=q.id;b.setAttribute('aria-label','Question '+(i+1));b.onclick=()=>load(q.id);nav.append(b)});stats();if(finalized){showResult();return}renderTimer();timerHandle=setInterval(renderTimer,1000);if(expired)document.getElementById('expired').classList.remove('hidden');if(questions.length)load(questions[0].id);else document.getElementById('title').textContent='No active questions. Contact your instructor.'}
document.getElementById('answerForm').onsubmit=async e=>{e.preventDefault();if(expired||finalized||!current)return;const q=current;let answer;if(q.qtype==='multiple_choice')answer=[...document.querySelectorAll('input[name="answer"]:checked')].map(x=>x.value);else if(q.qtype==='single_choice'||q.qtype==='true_false')answer=document.querySelector('input[name="answer"]:checked')?.value||'';else answer=document.getElementById('answerText').value;const btn=document.getElementById('saveBtn');btn.disabled=true;try{const r=await api('/api/submit',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({id:q.id,answer})});const d=await r.json();if(r.status===401){location.reload();return}if(!r.ok){message(d.error||'Could not save answer.');return}answeredSet.add(q.id);stats();message('Answer saved. No correctness feedback is provided. You can change it before final submission.')}catch(e){message('Network error. Check your connection and retry.')}finally{btn.disabled=expired||finalized}};
document.getElementById('clear').onclick=()=>{if(expired||finalized)return;document.querySelectorAll('#answerArea input').forEach(x=>{if(x.type==='checkbox'||x.type==='radio')x.checked=false;else x.value=''});message('Answer cleared in this view. Save a new answer to update your response.')};document.getElementById('next').onclick=()=>{if(!questions.length)return;const i=questions.findIndex(q=>q.id===current.id);load(questions[(i+1)%questions.length].id)};
async function showResult(){const r=await api('/api/result');if(!r.ok){location.reload();return}const d=await r.json();if(!d.result){message('Submit the exam when you are ready to see your final result.');return}finalized=true;clearInterval(timerHandle);document.getElementById('examMain').classList.add('hidden');const el=document.getElementById('result');el.classList.remove('hidden');const x=d.result;el.innerHTML=`<h1>Exam submitted</h1><p class="muted">Your final result</p><div style="font-size:48px;font-weight:800">${Number(x.percentage).toFixed(1)}%</div><h2 style="color:${x.passed?'#58d5b3':'#fecdd3'}">${x.passed?'PASS':'FAIL'}</h2><p>Score: <b>${x.score} / ${x.max_score}</b></p><p>Passing score: 70%</p><p class="muted">Your answers have been submitted and the result recorded.</p><a href="/choose-level">Return to level selection</a> · <a href="/logout">Sign out</a>`}
document.getElementById('finish').onclick=async()=>{if(finalized)return;const missing=questions.length-answeredSet.size;if(!expired&&missing>0){message(`Please answer all questions before final submission. ${missing} question(s) remain.`);return}if(!confirm('Submit your exam now? You cannot change answers after final submission.'))return;const b=document.getElementById('finish');b.disabled=true;try{const r=await api('/api/final-submit',{method:'POST',headers:{'Content-Type':'application/json'},body:'{}'});const d=await r.json();if(!r.ok){message(d.error||'Could not submit exam.');return}await showResult()}catch(e){message('Network error. Please try again.')}finally{b.disabled=finalized}};
document.getElementById('logout').onclick=async()=>{await api('/api/logout',{method:'POST'});location.href='/'};init();
</script></body></html>''' 

ADMIN_LOGIN=r'''<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Sunrise Staff Login</title><style>body{background:#0b1220;color:#e8eef8;font:16px system-ui;display:grid;place-items:center;min-height:100vh;margin:0;padding:20px}.card{background:#111c30;padding:24px;border:1px solid #263750;border-radius:14px;width:min(100%,440px)}input{width:100%;box-sizing:border-box;padding:12px;margin:8px 0;background:#09111f;color:#fff;border:1px solid #354965;border-radius:8px}button{padding:12px;width:100%;background:#58d5b3;border:0;border-radius:8px;font-weight:bold}.error{color:#fecdd3}.muted{color:#9aaec8;font-size:14px}</style></head><body><div class="card"><h1>Sunrise Staff Login</h1><p class="muted">Use your assigned staff username and password.</p><form method="post"><input type="hidden" name="csrf" value="{{csrf}}"><label>Username</label><input name="username" autocomplete="username" maxlength="80" required><label>Password</label><input type="password" name="password" autocomplete="current-password" required><button>Sign in</button></form>{% if error %}<p class="error">{{error}}</p>{% endif %}</div></body></html>'''

ADMIN_HTML=r'''<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Sunrise Instructor Dashboard</title><style>
body{margin:0;background:#0b1220;color:#e8eef8;font:15px/1.5 system-ui,Arial;padding:20px}main{max-width:1200px;margin:auto}.card{background:#111c30;border:1px solid #263750;border-radius:14px;padding:18px;margin:14px 0}input,select,textarea{padding:10px;background:#09111f;color:#fff;border:1px solid #354965;border-radius:8px;margin:5px;max-width:100%;box-sizing:border-box}button,.btn{padding:10px 14px;border:0;border-radius:8px;background:#58d5b3;color:#08231c;font-weight:bold;cursor:pointer}table{width:100%;border-collapse:collapse}td,th{text-align:left;border-bottom:1px solid #263750;padding:8px;vertical-align:top}.muted{color:#9aaec8}.alert{background:#3d321a;color:#f9e7a5;padding:12px;border-radius:8px}.success{background:#123f31;color:#a7f3d0;padding:12px;border-radius:8px}a{color:#9be8d2}.nav{display:flex;gap:10px;flex-wrap:wrap}.nav a{padding:9px 12px;border:1px solid #263750;border-radius:8px;text-decoration:none}code{overflow-wrap:anywhere}</style></head><body><main>
<h1>Sunrise CTF — Staff Dashboard</h1><p class="muted">Signed in as {{staff.full_name}} · {{role_label}}</p><div class="nav">{% if can_questions %}<a href="/admin/questions">Manage question bank</a><a href="/admin/answer-key.json">Download answer key</a><a href="/admin/questions/export.json">Export question bank</a>{% endif %}{% if can_results %}<a href="/admin/export.csv">Export results CSV</a>{% endif %}{% if can_users %}<a href="/admin/users">Manage users & roles</a>{% endif %}<a href="/admin/logout">Logout</a></div>
<div class="alert">Keep this portal, the private .env file, application source and answer keys away from students. Avoid editing question content during a live exam; changes affect both level portals immediately.</div>
{% if can_students %}<div class="card"><h2>Create candidate student</h2><form method="post" action="/admin/create"><input type="hidden" name="csrf" value="{{csrf}}"><input name="candidate_id" placeholder="Candidate ID (e.g. STU-001)" maxlength="80" required><input name="name" placeholder="Candidate name" maxlength="120" required><label>Exam access</label><label><input type="checkbox" name="allowed_levels" value="level1" checked> Level 1 — Ethical Hacking</label><label><input type="checkbox" name="allowed_levels" value="level2"> Level 2 — Penetration Testing</label><button>Create candidate + PIN</button></form>{% if new_candidate %}<div class="success"><b>Candidate:</b> {{new_candidate.candidate_id}} — {{new_candidate.name}}<br><b>PIN (shown once):</b> <code>{{new_candidate.pin}}</code></div>{% endif %}{% if error %}<p style="color:#fecdd3">{{error}}</p>{% endif %}</div>{% endif %}
{% if can_results %}<div class="card"><h2>Candidate results</h2><table><thead><tr><th>Candidate</th><th>Level 1</th><th>Level 2</th><th>Latest activity</th></tr></thead><tbody>{% for r in results %}<tr><td>{{r.candidate_id}}<br>{{r.name}}</td><td>{% if r.l1_percentage is not none %}<b>{{'PASS' if r.l1_passed else 'FAIL'}}</b> · {{'%.1f'|format(r.l1_percentage)}}%<br>{{r.l1_points}} / {{r.l1_max}} points{% else %}<span class="muted">Not submitted</span>{% endif %}</td><td>{% if r.l2_percentage is not none %}<b>{{'PASS' if r.l2_passed else 'FAIL'}}</b> · {{'%.1f'|format(r.l2_percentage)}}%<br>{{r.l2_points}} / {{r.l2_max}} points{% else %}<span class="muted">Not submitted</span>{% endif %}</td><td>{{r.last_activity or 'No submissions'}}</td></tr>{% endfor %}</tbody></table></div>{% endif %}
{% if can_questions %}<div class="card"><h2>Question bank summary</h2><p>Level 1: <b>{{l1_count}}</b> active / {{l1_all}} total questions. Level 2: <b>{{l2_count}}</b> active / {{l2_all}} total questions.</p><p>Supported types: flag, short text, single-choice MCQ, multiple-choice MCQ, and true/false.</p><a class="btn" href="/admin/questions">Add or modify questions</a></div>{% endif %}</main></body></html>'''

QUESTION_ADMIN=r'''<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Sunrise Question Manager</title><style>
:root{--bg:#0b1220;--panel:#111c30;--line:#263750;--text:#e8eef8;--muted:#9aaec8;--accent:#58d5b3}*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font:15px/1.5 system-ui,Arial;padding:20px}main{max-width:1320px;margin:auto}.card{background:var(--panel);border:1px solid var(--line);border-radius:16px;padding:20px;margin:16px 0}input,select,textarea{width:100%;box-sizing:border-box;padding:11px;background:#09111f;color:#fff;border:1px solid #354965;border-radius:9px;margin:5px 0 12px;font:inherit}textarea{min-height:110px}label{display:block;color:#c8d5e8;font-size:14px}button,.btn{padding:10px 14px;border:0;border-radius:9px;background:var(--accent);color:#08231c;font-weight:750;cursor:pointer;text-decoration:none;display:inline-block}button.danger{background:#b83350;color:white}.muted,.small{color:var(--muted);font-size:13px}.grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:12px}.option-row{display:grid;grid-template-columns:1fr auto auto;gap:10px;align-items:center;padding:10px;border:1px solid var(--line);border-radius:10px;margin:8px 0}.option-row input[type=checkbox],.option-row input[type=radio]{width:auto;margin:0}.actions{display:flex;gap:8px;align-items:center;flex-wrap:wrap}.success{background:#123f31;color:#a7f3d0;padding:12px;border-radius:8px}.error{background:#4a1d2a;color:#fecdd3;padding:12px;border-radius:8px}.notice{background:#3d321a;color:#f9e7a5;padding:12px;border-radius:8px}table{width:100%;border-collapse:collapse}td,th{text-align:left;border-bottom:1px solid var(--line);padding:9px;vertical-align:top}.table-wrap{overflow-x:auto}@media(max-width:760px){.grid{grid-template-columns:1fr}.option-row{grid-template-columns:1fr auto auto}table{font-size:13px}}
</style></head><body><main><h1>Question Bank</h1><p><a href="/admin">← Admin dashboard</a> · <a href="/admin/logout">Sign out</a></p><p class="muted">Choose a level, create as many questions as you need, and edit them using simple form fields. Changes appear in that level's student exam.</p>{% if message %}<div class="success">{{message}}</div>{% endif %}{% if error %}<div class="error">{{error}}</div>{% endif %}
<section class="card"><h2>{% if edit %}Edit question #{{edit.id}}{% else %}Add a question{% endif %}</h2><form id="questionForm" method="post" action="/admin/questions/save"><input type="hidden" name="csrf" value="{{csrf}}"><input type="hidden" name="id" value="{{edit.id if edit else ''}}"><input type="hidden" name="options_json" id="options_json"><input type="hidden" name="answer" id="answer_hidden"><div class="grid"><div><label>Exam level</label><select name="level" id="level" {% if edit %}disabled{% endif %}><option value="level1" {% if not edit or edit.level=='level1' %}selected{% endif %}>Level 1 — Ethical Hacking</option><option value="level2" {% if edit and edit.level=='level2' %}selected{% endif %}>Level 2 — Penetration Testing</option></select>{% if edit %}<input type="hidden" name="level" value="{{edit.level}}">{% endif %}</div><div><label>Question type</label><select name="qtype" id="qtype" onchange="updateType()"><option value="flag" {% if edit and edit.qtype=='flag' %}selected{% endif %}>Flag / CTF answer</option><option value="short_text" {% if edit and edit.qtype=='short_text' %}selected{% endif %}>Short text</option><option value="single_choice" {% if edit and edit.qtype=='single_choice' %}selected{% endif %}>Multiple choice — one answer</option><option value="multiple_choice" {% if edit and edit.qtype=='multiple_choice' %}selected{% endif %}>Multiple choice — several answers</option><option value="true_false" {% if edit and edit.qtype=='true_false' %}selected{% endif %}>True / False</option></select></div><div><label>Question title</label><input name="title" required maxlength="160" value="{{edit.title if edit else ''}}" placeholder="e.g. Identify the protocol"></div><div><label>Topic / category</label><input name="category" maxlength="100" value="{{edit.category if edit else 'General'}}" placeholder="e.g. Web Security"></div><div><label>Points</label><input type="number" name="points" min="1" max="10000" required value="{{edit.points if edit else 100}}"></div><div><label>Student visibility</label><select name="active"><option value="1" {% if not edit or edit.active %}selected{% endif %}>Published — visible to students</option><option value="0" {% if edit and not edit.active %}selected{% endif %}>Draft — hidden from students</option></select></div></div><label>Question instructions / scenario</label><textarea name="prompt" required maxlength="12000" placeholder="Write the question and any instructions the student needs.">{{edit.prompt if edit else ''}}</textarea>
<div id="mcqBuilder" class="card" style="margin:10px 0;display:none"><h3>Answer options</h3><p class="small">Write each option in a separate field. Tick the correct option(s). Students will not see which answer is correct during the exam.</p><div id="optionRows"></div><div class="actions"><button type="button" id="addOption" class="btn">+ Add option</button></div></div>
<div id="textAnswerWrap"><label id="answerLabel">Expected answer / flag</label><textarea id="textAnswer" placeholder="Enter the expected flag or accepted text answers. For short text, put each accepted answer on a new line.">{{edit_answer}}</textarea><p id="answerHelp" class="small">For flags, enter the expected flag. For short text, accepted answers can be entered one per line.</p></div><div id="trueFalseWrap" style="display:none"><label>Correct answer</label><select id="trueFalseAnswer"><option value="true">True</option><option value="false">False</option></select><p class="small">Choose the correct response.</p></div>
<div class="actions"><button type="submit">{% if edit %}Save changes{% else %}Add question{% endif %}</button><a class="btn" href="/admin/questions?level={{level_filter if level_filter in ['level1','level2'] else 'level1'}}">Cancel / add another</a></div></form></section>
<section class="card"><h2>Questions ({{questions|length}})</h2><form method="get"><label>Show questions for</label><select name="level" onchange="this.form.submit()"><option value="all" {% if level_filter=='all' %}selected{% endif %}>Both levels</option><option value="level1" {% if level_filter=='level1' %}selected{% endif %}>Level 1 — Ethical Hacking</option><option value="level2" {% if level_filter=='level2' %}selected{% endif %}>Level 2 — Penetration Testing</option></select></form><div class="table-wrap"><table><thead><tr><th>Number</th><th>Level</th><th>Question</th><th>Type</th><th>Points</th><th>Status</th><th>Actions</th></tr></thead><tbody>{% for q in questions %}<tr><td>{{loop.index}}</td><td>{{'Level 1' if q.level=='level1' else 'Level 2'}}</td><td><b>{{q.title}}</b><br><span class="muted">{{q.category}}</span></td><td>{{q.qtype.replace('_',' ')}}</td><td>{{q.points}}</td><td>{{'Published' if q.active else 'Draft'}}</td><td><div class="actions"><a class="btn" href="/admin/questions?edit={{q.id}}&level={{level_filter}}">Edit</a><form method="post" action="/admin/questions/delete" onsubmit="return confirm('Delete this question? This cannot be undone.');"><input type="hidden" name="csrf" value="{{csrf}}"><input type="hidden" name="id" value="{{q.id}}"><button type="submit" class="danger">Delete</button></form></div></td></tr>{% else %}<tr><td colspan="7">No questions yet. Use the form above to add your first question.</td></tr>{% endfor %}</tbody></table></div></section></main>
<script>
const initialOptions={{options_data|tojson}};const initialAnswer={{answer_data|tojson}};const rows=document.getElementById('optionRows');
function letter(i){return String.fromCharCode(65+i)}
function addOption(label='',value='',correct=false){if(rows.children.length>=50){alert('A question can have up to 50 options.');return}const idx=rows.children.length;const row=document.createElement('div');row.className='option-row';row.dataset.value=value||letter(idx);const input=document.createElement('input');input.type='text';input.className='option-label';input.placeholder='Option '+letter(idx);input.maxLength=500;input.value=label;const choose=document.createElement('label');choose.style.display='flex';choose.style.gap='6px';choose.style.alignItems='center';const check=document.createElement('input');check.type='checkbox';check.className='correct-option';check.checked=correct;check.onchange=()=>{if(document.getElementById('qtype').value==='single_choice'&&check.checked)[...rows.querySelectorAll('.correct-option')].forEach(other=>{if(other!==check)other.checked=false})};choose.append(check,document.createTextNode('Correct'));const remove=document.createElement('button');remove.type='button';remove.className='danger';remove.textContent='Remove';remove.onclick=()=>{row.remove();renumber()};row.append(input,choose,remove);rows.append(row)}
function renumber(){[...rows.children].forEach((row,i)=>{row.dataset.value=letter(i);row.querySelector('.option-label').placeholder='Option '+letter(i)})}
function updateType(){const t=document.getElementById('qtype').value;const mcq=['single_choice','multiple_choice'].includes(t);document.getElementById('mcqBuilder').style.display=mcq?'block':'none';document.getElementById('textAnswerWrap').style.display=(!mcq&&t!=='true_false')?'block':'none';document.getElementById('trueFalseWrap').style.display=t==='true_false'?'block':'none';if(t==='true_false'){document.getElementById('trueFalseAnswer').value=String(initialAnswer||'true').toLowerCase()}else if(t==='flag'){document.getElementById('answerLabel').textContent='Expected flag';document.getElementById('answerHelp').textContent='Enter the exact expected flag. Students will not receive correctness feedback.'}else if(t==='short_text'){document.getElementById('answerLabel').textContent='Accepted text answers';document.getElementById('answerHelp').textContent='Enter one accepted answer per line.'}}
document.getElementById('addOption').onclick=()=>addOption();
if(initialOptions.length){const correctVals=Array.isArray(initialAnswer)?initialAnswer.map(String):String(initialAnswer||'').split(',').map(x=>x.trim());initialOptions.forEach(o=>addOption(o.label,o.value,correctVals.includes(String(o.value))))}else{addOption();addOption();addOption();addOption()}
updateType();
document.getElementById('questionForm').onsubmit=e=>{const t=document.getElementById('qtype').value;if(['single_choice','multiple_choice'].includes(t)){const all=[...rows.children].map((row,i)=>({value:letter(i),label:row.querySelector('.option-label').value.trim(),correct:row.querySelector('.correct-option').checked}));if(all.length<2||all.some(x=>!x.label)){e.preventDefault();alert('Add at least two options and fill in each option.');return}const chosen=all.filter(x=>x.correct).map(x=>x.value);if(!chosen.length||(t==='single_choice'&&chosen.length!==1)){e.preventDefault();alert(t==='single_choice'?'Select exactly one correct option.':'Select at least one correct option.');return}document.getElementById('options_json').value=JSON.stringify(all.map(x=>({value:x.value,label:x.label})));document.getElementById('answer_hidden').value=t==='single_choice'?chosen[0]:chosen.join(',')}else{document.getElementById('options_json').value='[]';let ans=t==='true_false'?document.getElementById('trueFalseAnswer').value:document.getElementById('textAnswer').value.trim();if(!ans){e.preventDefault();alert('Enter the expected answer.');return}document.getElementById('answer_hidden').value=ans}};
</script></body></html>'''

LEVEL_PICKER_HTML=r'''<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Choose exam level</title><style>body{margin:0;background:#0b1220;color:#e8eef8;font:16px system-ui;min-height:100vh;display:grid;place-items:center;padding:20px}.card{width:min(100%,620px);background:#111c30;border:1px solid #263750;border-radius:18px;padding:28px}a{color:#9be8d2}.levels{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:14px;margin:22px 0}.level{display:block;padding:22px;border:1px solid #354965;border-radius:14px;background:#17253b;color:#fff;width:100%;font:inherit}.muted{color:#9aaec8}</style></head><body><section class="card"><h1>Choose your exam</h1><p class="muted">Welcome, {{candidate_name}}. Select one of the levels assigned to your account.</p><div class="levels">{% for lev in levels %}<form method="post" action="/select-level"><input type="hidden" name="csrf" value="{{csrf}}"><input type="hidden" name="level" value="{{lev}}"><button class="level" type="submit">{{titles[lev]}}<br><small>Open exam →</small></button></form>{% endfor %}</div><p><a href="/logout">Sign out</a></p></section></body></html>'''
RESULT_HTML=r'''<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Exam result</title><style>body{margin:0;background:#0b1220;color:#e8eef8;font:16px system-ui;min-height:100vh;display:grid;place-items:center;padding:20px}.card{width:min(100%,560px);background:#111c30;border:1px solid #263750;border-radius:18px;padding:30px;text-align:center}.score{font-size:48px;font-weight:800;margin:12px}.pass{color:#58d5b3}.fail{color:#fecdd3}.muted{color:#9aaec8}a{color:#9be8d2}</style></head><body><section class="card"><h1>Exam submitted</h1><p class="muted">{{level_title}}</p><div class="score">{{'%.1f'|format(result.percentage)}}%</div><h2 class="{{'pass' if result.passed else 'fail'}}">{{'PASS' if result.passed else 'FAIL'}}</h2><p>Score: <b>{{result.score}} / {{result.max_score}}</b></p><p>Passing requirement: 70%</p><p><a href="/choose-level">Return to level selection</a> · <a href="/logout">Sign out</a></p></section></body></html>'''
@app.get('/')
def index():
    if session.get('staff_user_id'): return redirect('/admin')
    cid=session.get('candidate_id')
    if not cid or not candidate_info(cid):
        title = "Sign in to access your assigned exam" if LEVEL == "both" else LEVEL_TITLES[LEVEL]
        return render_template_string(LOGIN_HTML,csrf=csrf_token(),level_title=title)
    allowed=[x for x in allowed_levels_for(cid) if LEVEL=='both' or x==LEVEL]
    if not allowed:
        session.clear(); return render_template_string(LOGIN_HTML,csrf=csrf_token(),level_title="No exam levels assigned")
    lev=active_level()
    if not lev or lev not in allowed:
        if len(allowed)==1: session['exam_level']=allowed[0]; lev=allowed[0]
        else: return render_template_string(LEVEL_PICKER_HTML,csrf=csrf_token(),candidate_name=candidate_info(cid)['name'],levels=allowed,titles=LEVEL_TITLES)
    with db() as con: result=con.execute("SELECT score,max_score,percentage,passed,submitted_at FROM exam_results WHERE candidate_id=? AND level=?",(cid,lev)).fetchone()
    if result: return render_template_string(RESULT_HTML,level_title=LEVEL_TITLES[lev],result=dict(result))
    ci=candidate_info(cid)
    return render_template_string(EXAM_HTML,csrf=csrf_token(),level_title=LEVEL_TITLES[lev],candidate_name=ci['name'],candidate_id=ci['candidate_id'])
@app.get('/choose-level')
def choose_level_page():
    session.pop('exam_level',None)
    return redirect('/')
@app.post('/api/login')
def login():
    if not check_csrf(): return jsonify({'error':'Session expired. Refresh and try again.'}),400
    body=request.get_json(silent=True) or {}; cid=str(body.get('candidate_id','')).strip(); pin=str(body.get('pin','')).strip()
    if not cid or not pin or len(cid)>80 or len(pin)>80: return jsonify({'error':'Enter candidate ID and PIN.'}),400
    with db() as con: row=con.execute('SELECT candidate_id,name,pin_salt,pin_hash,active,allowed_levels FROM candidates WHERE candidate_id=?',(cid,)).fetchone()
    if not row or not row['active'] or not hmac.compare_digest(pin_hash(pin,row['pin_salt']),row['pin_hash']):
        time.sleep(0.25); return jsonify({'error':'Candidate ID or PIN is incorrect.'}),401
    allowed=[x for x in (row['allowed_levels'] or '').split(',') if x in ('level1','level2') and (LEVEL=='both' or x==LEVEL)]
    if not allowed: return jsonify({'error':'You are not assigned to an available exam level. Contact the exam administrator.'}),403
    session.clear(); session['candidate_id']=row['candidate_id']; session['csrf']=secrets.token_urlsafe(24); session.permanent=True
    if len(allowed)==1: session['exam_level']=allowed[0]
    return jsonify({'ok':True,'choose_level':len(allowed)>1})
@app.post('/select-level')
def select_level():
    if not check_csrf(request.form.get('csrf')): return redirect('/?error=Session+expired')
    cid=session.get('candidate_id'); lev=request.form.get('level','')
    if not cid or lev not in ('level1','level2') or (LEVEL!='both' and lev!=LEVEL) or lev not in allowed_levels_for(cid): return redirect('/')
    session['exam_level']=lev; return redirect('/')
@app.post('/api/logout')
def logout_api():
    if not check_csrf(): return jsonify({'error':'Invalid request.'}),400
    session.clear(); return jsonify({'ok':True})
@app.get('/logout')
def logout_page():
    session.clear(); return redirect('/')
@app.get('/api/challenges')
@student_required
def list_challenges():
    cid=session['candidate_id']; lev=active_level(); status=exam_status(cid,start=True,level=lev); questions=get_questions(lev)
    with db() as con:
        answered_rows=con.execute('SELECT question_id FROM exam_answers WHERE candidate_id=? AND level=?',(cid,lev)).fetchall()
        result=con.execute('SELECT 1 FROM exam_results WHERE candidate_id=? AND level=?',(cid,lev)).fetchone()
    answered=[r['question_id'] for r in answered_rows]
    return jsonify({'questions':[{'id':q['id'],'title':q['title'],'qtype':q['qtype'],'points':q['points']} for q in questions], 'total':len(questions),'answered':answered,'max_points':sum(int(q['points']) for q in questions),'deadline_at':status['deadline_at'],'expired':status['expired'],'finalized':bool(result),'level':lev})
@app.get('/api/challenge/<int:question_id>')
@student_required
def get_challenge(question_id):
    lev=active_level(); cid=session['candidate_id']; status=exam_status(cid,start=True,level=lev)
    if status['expired']: return jsonify({'expired':True,'error':'Exam time has ended.'}),403
    q=get_question(question_id,lev)
    if not q: return jsonify({'error':'Question not found.'}),404
    with db() as con:
        saved=con.execute('SELECT answer_json FROM exam_answers WHERE candidate_id=? AND level=? AND question_id=?',(cid,lev,question_id)).fetchone()
        final=con.execute('SELECT 1 FROM exam_results WHERE candidate_id=? AND level=?',(cid,lev)).fetchone()
    data=public_question(q,False); data['saved_answer']=json.loads(saved['answer_json']) if saved else None; data['finalized']=bool(final)
    return jsonify(data)
@app.post('/api/submit')
@student_required
def submit():
    if not check_csrf(): return jsonify({'error':'Invalid request token. Refresh the page.'}),400
    if getattr(request,'exam_finalized',False): return jsonify({'error':'This exam has already been submitted.'}),409
    body=request.get_json(silent=True) or {}
    try: qid=int(body.get('id',0))
    except (TypeError,ValueError): return jsonify({'error':'Invalid question.'}),400
    lev=active_level(); cid=session['candidate_id']; q=get_question(qid,lev)
    if not q: return jsonify({'error':'Question not found or inactive.'}),400
    status=exam_status(cid,start=True,level=lev)
    if status['expired']: return jsonify({'expired':True,'error':'Time has ended. Submit the exam for your result.'}),403
    answer=body.get('answer',body.get('flag',''))
    if isinstance(answer,str): answer=answer.strip()
    if answer in ('',[],None): return jsonify({'error':'Enter or select an answer before saving.'}),400
    with db() as con:
        con.execute('INSERT INTO exam_answers(candidate_id,level,question_id,answer_json,updated_at) VALUES(?,?,?,?,?) ON CONFLICT(candidate_id,level,question_id) DO UPDATE SET answer_json=excluded.answer_json,updated_at=excluded.updated_at',(cid,lev,qid,json.dumps(answer,ensure_ascii=False),iso(utcnow())))
        con.execute('INSERT INTO submissions(candidate_id,level,challenge_id,correct,submitted_at) VALUES(?,?,?,?,?)',(cid,lev,qid,0,iso(utcnow())))
        answered=con.execute('SELECT COUNT(*) n FROM exam_answers WHERE candidate_id=? AND level=?',(cid,lev)).fetchone()['n']
        total=con.execute('SELECT COUNT(*) n FROM questions WHERE level=? AND active=1',(lev,)).fetchone()['n']
    return jsonify({'saved':True,'answered':answered,'total':total,'message':'Answer saved.'})
@app.get('/api/result')
@student_required
def get_result():
    with db() as con: row=con.execute('SELECT score,max_score,percentage,passed,submitted_at FROM exam_results WHERE candidate_id=? AND level=?',(session['candidate_id'],active_level())).fetchone()
    return jsonify({'result':dict(row) if row else None})
@app.post('/api/final-submit')
@student_required
def final_submit():
    if not check_csrf(): return jsonify({'error':'Invalid request token.'}),400
    cid=session['candidate_id']; lev=active_level(); now=iso(utcnow())
    with db() as con:
        prior=con.execute('SELECT score,max_score,percentage,passed,submitted_at FROM exam_results WHERE candidate_id=? AND level=?',(cid,lev)).fetchone()
        if prior: return jsonify({'ok':True,'result':dict(prior),'already_submitted':True})
        qs=con.execute('SELECT * FROM questions WHERE level=? AND active=1 ORDER BY id',(lev,)).fetchall()
        saved={r['question_id']:json.loads(r['answer_json']) for r in con.execute('SELECT question_id,answer_json FROM exam_answers WHERE candidate_id=? AND level=?',(cid,lev)).fetchall()}
        answered=sum(1 for q in qs if q['id'] in saved and saved[q['id']] not in ('',[],None))
        status=exam_status(cid,start=False,level=lev)
        if answered<len(qs) and not status['expired']:
            return jsonify({'error':f'Please answer all questions before final submission. Answered {answered} of {len(qs)}.'}),400
        score=0; max_score=sum(int(q['points']) for q in qs)
        for q in qs:
            if q['id'] in saved and answers_match(dict(q),saved[q['id']]): score += int(q['points'])
        pct=(score/max_score*100) if max_score else 0.0; passed=1 if pct>=70.0 else 0
        con.execute('INSERT INTO exam_results(candidate_id,level,score,max_score,percentage,passed,submitted_at) VALUES(?,?,?,?,?,?,?)',(cid,lev,score,max_score,pct,passed,now))
    return jsonify({'ok':True,'result':{'score':score,'max_score':max_score,'percentage':pct,'passed':passed,'submitted_at':now}})

@app.get('/admin/login')
def admin_login_page(): return render_template_string(ADMIN_LOGIN,csrf=csrf_token(),error=None)
@app.post('/admin/login')
def admin_login_post():
    if not check_csrf(request.form.get('csrf')): return render_template_string(ADMIN_LOGIN,csrf=csrf_token(),error='Session expired. Refresh and try again.'),400
    username=request.form.get('username','').strip().lower(); password=request.form.get('password','')
    with db() as con: row=con.execute('SELECT * FROM staff_users WHERE username=?',(username,)).fetchone()
    if not row or not row['active'] or not hmac.compare_digest(password_hash(password,row['password_salt']),row['password_hash']):
        time.sleep(0.25); return render_template_string(ADMIN_LOGIN,csrf=csrf_token(),error='Username or password is incorrect.'),401
    session.clear(); session['staff_user_id']=row['id']; session['role']=row['role']; session['csrf']=secrets.token_urlsafe(24); session.permanent=True
    audit('login','staff_user:'+username,'Successful staff login')
    return redirect('/admin')

def admin_results():
    with db() as con:
        candidates=con.execute('SELECT candidate_id,name FROM candidates ORDER BY candidate_id').fetchall(); results=[]
        for c in candidates:
            row={'candidate_id':c['candidate_id'],'name':c['name']}
            for lev,prefix in (('level1','l1'),('level2','l2')):
                res=con.execute('SELECT score,max_score,percentage,passed,submitted_at FROM exam_results WHERE candidate_id=? AND level=?',(c['candidate_id'],lev)).fetchone()
                sess=con.execute('SELECT deadline_at FROM exam_sessions WHERE candidate_id=? AND level=?',(c['candidate_id'],lev)).fetchone()
                row[prefix+'_solved']=0
                row[prefix+'_points']=res['score'] if res else 0
                row[prefix+'_max']=res['max_score'] if res else 0
                row[prefix+'_percentage']=res['percentage'] if res else None
                row[prefix+'_passed']=res['passed'] if res else None
                row[prefix+'_deadline']=sess['deadline_at'] if sess else None
            row['last_activity']=con.execute('SELECT MAX(submitted_at) t FROM submissions WHERE candidate_id=?',(c['candidate_id'],)).fetchone()['t']
            row['last_activity']=row['last_activity'] or con.execute('SELECT MAX(submitted_at) t FROM exam_results WHERE candidate_id=?',(c['candidate_id'],)).fetchone()['t']
            results.append(row)
        return results

def render_dashboard(new_candidate=None,error=None):
    with db() as con:
        counts={}
        for lev in ('level1','level2'):
            r=con.execute('SELECT COUNT(*) total,COALESCE(SUM(active),0) active FROM questions WHERE level=?',(lev,)).fetchone(); counts[lev]=(r['total'],r['active'])
    staff=current_staff(); perms=ROLE_PERMISSIONS.get(staff['role'],set())
    return render_template_string(ADMIN_HTML,csrf=csrf_token(),results=admin_results() if 'view_results' in perms else [],new_candidate=new_candidate,error=error,l1_count=counts['level1'][1],l1_all=counts['level1'][0],l2_count=counts['level2'][1],l2_all=counts['level2'][0],staff=staff,role_label=ROLE_LABELS.get(staff['role'],staff['role']),can_questions='manage_questions' in perms,can_results='view_results' in perms,can_students='manage_students' in perms,can_users='manage_users' in perms)

@app.get('/admin')
@permission_required()
def admin_dashboard():
    return render_dashboard(error=request.args.get('error'))

@app.post('/admin/create')
@permission_required('manage_students')
def admin_create():
    if not check_csrf(request.form.get('csrf')): return redirect('/admin')
    cid=request.form.get('candidate_id','').strip(); name=request.form.get('name','').strip()
    levels=sorted(set(request.form.getlist('allowed_levels')) & {'level1','level2'})
    if not cid or not name or len(cid)>80 or len(name)>120 or not levels: return render_dashboard(error='Enter a valid candidate ID/name and select at least one exam level.'),400
    allowed_levels=','.join(levels)
    pin=secrets.token_urlsafe(9); salt=secrets.token_hex(16)
    try:
        with db() as con: con.execute('INSERT INTO candidates(candidate_id,name,pin_salt,pin_hash,created_at,allowed_levels) VALUES(?,?,?,?,?,?)',(cid,name,salt,pin_hash(pin,salt),iso(utcnow()),allowed_levels))
    except sqlite3.IntegrityError: return redirect('/admin?error=Candidate+ID+already+exists')
    audit('create_student',cid,'Student candidate created')
    return render_dashboard(new_candidate={'candidate_id':cid,'name':name,'pin':pin})

@app.get('/admin/questions')
@permission_required('manage_questions')
def admin_questions():
    filt=request.args.get('level','all'); edit_id=request.args.get('edit',type=int); edit=None; edit_answer=''; options_json='[]'; options_data=[]; answer_data=''
    with db() as con:
        if edit_id:
            r=con.execute('SELECT * FROM questions WHERE id=?',(edit_id,)).fetchone()
            if r:
                edit=dict(r); options_data=json.loads(edit['options_json'] or '[]'); options_json=json.dumps(options_data,ensure_ascii=False); ans=json.loads(edit['answer_json']); answer_data=ans
                edit_answer=(','.join(map(str,ans)) if edit['qtype']=='multiple_choice' else '\n'.join(map(str,ans))) if isinstance(ans,list) else str(ans)
        if filt in ('level1','level2'): rows=con.execute('SELECT * FROM questions WHERE level=? ORDER BY level,id',(filt,)).fetchall()
        else: rows=con.execute('SELECT * FROM questions ORDER BY level,id').fetchall(); filt='all'
    qs=[dict(r) for r in rows]
    return render_template_string(QUESTION_ADMIN,csrf=csrf_token(),questions=qs,edit=edit,edit_answer=edit_answer,options_json=options_json,options_data=options_data,answer_data=answer_data,level_filter=filt,message=request.args.get('message'),error=request.args.get('error'))

@app.post('/admin/questions/save')
@permission_required('manage_questions')
def admin_question_save():
    if not check_csrf(request.form.get('csrf')): return redirect('/admin/questions?error=Session+expired')
    raw_id=request.form.get('id','').strip(); existing=None
    if raw_id:
        try: qid=int(raw_id)
        except ValueError: return redirect('/admin/questions?error=Invalid+question+ID')
        with db() as con:
            r=con.execute('SELECT * FROM questions WHERE id=?',(qid,)).fetchone(); existing=dict(r) if r else None
        if not existing: return redirect('/admin/questions?error=Question+not+found')
    try: clean=validate_question_form(request.form,existing)
    except ValueError as e: return redirect('/admin/questions?error='+quote(str(e)))
    now=iso(utcnow())
    with db() as con:
        if existing:
            con.execute('UPDATE questions SET title=?,prompt=?,category=?,qtype=?,options_json=?,answer_json=?,points=?,active=?,updated_at=? WHERE id=?',
                (clean['title'],clean['prompt'],clean['category'],clean['qtype'],clean['options_json'],clean['answer_json'],clean['points'],clean['active'],now,existing['id']))
        else:
            con.execute('INSERT INTO questions(level,title,prompt,category,qtype,options_json,answer_json,points,active,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)',
                (clean['level'],clean['title'],clean['prompt'],clean['category'],clean['qtype'],clean['options_json'],clean['answer_json'],clean['points'],clean['active'],now,now))
    return redirect('/admin/questions?level='+clean['level']+'&message='+quote('Question saved successfully.'))

@app.post('/admin/questions/delete')
@permission_required('manage_questions')
def admin_question_delete():
    if not check_csrf(request.form.get('csrf')): return redirect('/admin/questions?error=Session+expired')
    try: qid=int(request.form.get('id','0'))
    except ValueError: return redirect('/admin/questions?error=Invalid+question+ID')
    with db() as con:
        row=con.execute('SELECT level FROM questions WHERE id=?',(qid,)).fetchone()
        if row:
            con.execute('DELETE FROM solves WHERE challenge_id=? AND level=?',(qid,row['level']))
            con.execute('DELETE FROM questions WHERE id=?',(qid,))
            return redirect('/admin/questions?level='+row['level']+'&message=Question+deleted')
    return redirect('/admin/questions?error=Question+not+found')

@app.get('/admin/answer-key.json')
@permission_required('view_answer_key')
def admin_answer_key():
    with db() as con:
        rows=con.execute('SELECT id,level,title,qtype,answer_json,points,active FROM questions ORDER BY level,id').fetchall()
    data=[{'id':r['id'],'level':r['level'],'title':r['title'],'type':r['qtype'],'answer':json.loads(r['answer_json']),'points':r['points'],'active':bool(r['active'])} for r in rows]
    resp=make_response(json.dumps(data,ensure_ascii=False,indent=2)); resp.headers['Content-Type']='application/json; charset=utf-8'; resp.headers['Content-Disposition']='attachment; filename="sunrise_current_answer_key.json"'; return resp

@app.get('/admin/questions/export.json')
@permission_required('manage_questions')
def admin_question_export():
    with db() as con: rows=con.execute('SELECT id,level,title,prompt,category,qtype,options_json,answer_json,points,active FROM questions ORDER BY level,id').fetchall()
    data=[]
    for r in rows:
        item=dict(r); item['options']=json.loads(item.pop('options_json')); item['answer']=json.loads(item.pop('answer_json')); item['active']=bool(item['active']); data.append(item)
    resp=make_response(json.dumps(data,ensure_ascii=False,indent=2)); resp.headers['Content-Type']='application/json; charset=utf-8'; resp.headers['Content-Disposition']='attachment; filename="sunrise_question_bank_backup.json"'; return resp

@app.get('/admin/export.csv')
@permission_required('view_results')
def admin_export():
    out=io.StringIO(); w=csv.writer(out); w.writerow(['candidate_id','name','level1_score','level1_max','level1_percentage','level1_result','level2_score','level2_max','level2_percentage','level2_result','latest_activity'])
    for r in admin_results(): w.writerow([r['candidate_id'],r['name'],r['l1_points'],r['l1_max'],r['l1_percentage'] if r['l1_percentage'] is not None else '',('PASS' if r['l1_passed'] else 'FAIL') if r['l1_passed'] is not None else '',r['l2_points'],r['l2_max'],r['l2_percentage'] if r['l2_percentage'] is not None else '',('PASS' if r['l2_passed'] else 'FAIL') if r['l2_passed'] is not None else '',r['last_activity'] or ''])
    resp=make_response(out.getvalue()); resp.headers['Content-Type']='text/csv; charset=utf-8'; resp.headers['Content-Disposition']='attachment; filename="sunrise_ctf_results.csv"'; return resp
@app.get('/admin/users')
@permission_required('manage_users')
def admin_users():
    with db() as con:
        users=[dict(r) for r in con.execute('SELECT id,username,full_name,role,active,created_at FROM staff_users ORDER BY username').fetchall()]
        students=[dict(r) for r in con.execute('SELECT candidate_id,name,active,allowed_levels FROM candidates ORDER BY candidate_id').fetchall()]
    for u in users: u['role_label']=ROLE_LABELS[u['role']]
    permissions={r:set(ROLE_PERMISSIONS.get(r,set())) for r in ('super_admin','exam_admin','instructor')}; permissions['student']=set()
    labels={'manage_users':'Manage staff users and roles','manage_students':'Create/manage student accounts','manage_questions':'Add/edit/delete questions','view_results':'View/export exam results','manage_exams':'Manage exam configuration','view_answer_key':'View/export answer keys'}
    template=Path(__file__).with_name('roles.html').read_text(encoding='utf-8')
    return render_template_string(template,csrf=csrf_token(),staff_users=users,students=students,roles=ROLE_LABELS,permissions=permissions,permission_labels=labels,message=request.args.get('message'),error=request.args.get('error'),created_user=None)

@app.post('/admin/users/create')
@permission_required('manage_users')
def admin_users_create():
    if not check_csrf(request.form.get('csrf')): return redirect('/admin/users?error=Session+expired')
    username=request.form.get('username','').strip().lower(); full_name=request.form.get('full_name','').strip(); role=request.form.get('role','')
    if not re.fullmatch(r'[a-z0-9][a-z0-9._-]{2,79}',username) or not full_name or len(full_name)>120 or role not in ('super_admin','exam_admin','instructor'):
        return redirect('/admin/users?error=Invalid+username,+name,+or+role')
    password=secrets.token_urlsafe(18); salt=secrets.token_hex(16); now=iso(utcnow())
    try:
        with db() as con: con.execute('INSERT INTO staff_users(username,full_name,role,password_salt,password_hash,active,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?)',(username,full_name,role,salt,password_hash(password,salt),1,now,now))
    except sqlite3.IntegrityError: return redirect('/admin/users?error=Username+already+exists')
    audit('create_staff_user',username,'role='+role)
    with db() as con:
        users=[dict(r) for r in con.execute('SELECT id,username,full_name,role,active,created_at FROM staff_users ORDER BY username').fetchall()]
        students=[dict(r) for r in con.execute('SELECT candidate_id,name,active,allowed_levels FROM candidates ORDER BY candidate_id').fetchall()]
    for u in users: u['role_label']=ROLE_LABELS[u['role']]
    permissions={r:set(ROLE_PERMISSIONS.get(r,set())) for r in ('super_admin','exam_admin','instructor')}; permissions['student']=set()
    labels={'manage_users':'Manage staff users and roles','manage_students':'Create/manage student accounts','manage_questions':'Add/edit/delete questions','view_results':'View/export exam results','manage_exams':'Manage exam configuration','view_answer_key':'View/export answer keys'}
    template=Path(__file__).with_name('roles.html').read_text(encoding='utf-8')
    return render_template_string(template,csrf=csrf_token(),staff_users=users,students=students,roles=ROLE_LABELS,permissions=permissions,permission_labels=labels,message=None,error=None,created_user={'username':username,'role_label':ROLE_LABELS[role],'password':password})

@app.post('/admin/users/update')
@permission_required('manage_users')
def admin_users_update():
    if not check_csrf(request.form.get('csrf')): return redirect('/admin/users?error=Session+expired')
    try: uid=int(request.form.get('id','0'))
    except ValueError: return redirect('/admin/users?error=Invalid+user+ID')
    role=request.form.get('role',''); active=1 if request.form.get('active')=='1' else 0
    if role not in ('super_admin','exam_admin','instructor'): return redirect('/admin/users?error=Invalid+role')
    with db() as con:
        target=con.execute('SELECT id,username,role,active FROM staff_users WHERE id=?',(uid,)).fetchone()
        if not target: return redirect('/admin/users?error=User+not+found')
        if target['id']==session.get('staff_user_id') and (not active or role!='super_admin'):
            return redirect('/admin/users?error=You+cannot+disable+or+demote+your+own+Super+Admin+account')
        if target['role']=='super_admin' and (not active or role!='super_admin'):
            count=con.execute("SELECT COUNT(*) n FROM staff_users WHERE role='super_admin' AND active=1").fetchone()['n']
            if count<=1: return redirect('/admin/users?error=Cannot+disable+or+demote+the+last+active+Super+Admin')
        con.execute('UPDATE staff_users SET role=?,active=?,updated_at=? WHERE id=?',(role,active,iso(utcnow()),uid))
    audit('update_staff_user',target['username'],f'role={role};active={active}')
    return redirect('/admin/users?message=User+updated')

@app.post('/admin/users/student-access')
@permission_required('manage_users')
def admin_student_access():
    if not check_csrf(request.form.get('csrf')): return redirect('/admin/users?error=Session+expired')
    cid=request.form.get('candidate_id','').strip()
    levels=sorted(set(request.form.getlist('allowed_levels')) & {'level1','level2'})
    if not levels: return redirect('/admin/users?error=Select+at+least+one+exam+level')
    allowed_levels=','.join(levels)
    with db() as con:
        cur=con.execute('UPDATE candidates SET allowed_levels=? WHERE candidate_id=?',(allowed_levels,cid))
        if cur.rowcount==0: return redirect('/admin/users?error=Student+not+found')
    audit('update_student_access',cid,'allowed_levels='+allowed_levels)
    return redirect('/admin/users?message=Student+exam+access+updated')

@app.post('/admin/users/student-status')
@permission_required('manage_users')
def admin_student_status():
    if not check_csrf(request.form.get('csrf')): return redirect('/admin/users?error=Session+expired')
    cid=request.form.get('candidate_id','').strip(); active=1 if request.form.get('active')=='1' else 0
    with db() as con:
        cur=con.execute('UPDATE candidates SET active=? WHERE candidate_id=?',(active,cid))
        if cur.rowcount==0: return redirect('/admin/users?error=Student+not+found')
    audit('update_student_status',cid,f'active={active}')
    return redirect('/admin/users?message=Student+status+updated')

@app.get('/admin/logout')
def admin_logout():
    if session.get('staff_user_id'): audit('logout','staff_user:'+str(session.get('staff_user_id')),'Staff logout')
    session.clear(); return redirect('/admin/login')
@app.get('/health')
@app.get('/healthz')
def health():
    try:
        with db() as con:
            con.execute('SELECT 1'); n=con.execute('SELECT COUNT(*) n FROM questions WHERE active=1').fetchone()['n']
        return jsonify({'status':'ok','mode':LEVEL,'active_questions':n})
    except Exception: return jsonify({'status':'error'}),500

if __name__=='__main__': app.run(host='0.0.0.0',port=PORT,debug=False)
