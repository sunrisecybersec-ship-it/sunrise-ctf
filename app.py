import os, json, sqlite3, secrets, hashlib, hmac, time, csv, io, re
from urllib.parse import quote
from contextlib import contextmanager
from datetime import datetime, timezone, timedelta
from functools import wraps
from pathlib import Path
from flask import Flask, request, jsonify, session, render_template_string, redirect, make_response, url_for

LEVEL = os.environ.get("LEVEL", "level1").lower()
if LEVEL not in ("level1", "level2"):
    raise RuntimeError("LEVEL must be level1 or level2")
PORT = int(os.environ.get("PORT", "8001" if LEVEL == "level1" else "8002"))
DB_PATH = os.environ.get("DB_PATH", "/data/exam.db")
SECRET_KEY = os.environ.get("SECRET_KEY")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD")
DURATION_MINUTES = int(os.environ.get("DURATION_MINUTES", "60" if LEVEL == "level1" else "120"))
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
        if LEVEL not in (active["allowed_levels"] or "").split(","):
            session.clear(); return jsonify({"error":"Your account is not assigned to this exam level. Contact the exam administrator."}),403
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
def get_question(qid, level=LEVEL, active_only=True):
    with db() as con:
        q="SELECT * FROM questions WHERE id=? AND level=?"+(" AND active=1" if active_only else "")
        r=con.execute(q,(qid,level)).fetchone()
        return dict(r) if r else None
def public_question(q, solved=False):
    return {"id":q["id"],"title":q["title"],"prompt":q["prompt"],"category":q["category"],"qtype":q["qtype"],
            "options":json.loads(q["options_json"] or "[]"),"points":q["points"],"solved":solved}
def exam_status(cid,start=False):
    now=utcnow()
    with db() as con:
        row=con.execute("SELECT started_at,deadline_at FROM exam_sessions WHERE candidate_id=? AND level=?",(cid,LEVEL)).fetchone()
        if row is None and start:
            deadline=now+timedelta(minutes=DURATION_MINUTES)
            con.execute("INSERT OR IGNORE INTO exam_sessions(candidate_id,level,started_at,deadline_at) VALUES(?,?,?,?)",(cid,LEVEL,iso(now),iso(deadline)))
            row=con.execute("SELECT started_at,deadline_at FROM exam_sessions WHERE candidate_id=? AND level=?",(cid,LEVEL)).fetchone()
    if row is None: return {"started":False,"expired":False,"remaining_seconds":DURATION_MINUTES*60,"deadline_at":None}
    deadline=datetime.fromisoformat(row["deadline_at"])
    remaining=max(0,int((deadline-now).total_seconds()))
    return {"started":True,"expired":remaining<=0,"remaining_seconds":remaining,"deadline_at":row["deadline_at"]}

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
        if not isinstance(options,list) or len(options)<2 or len(options)>12: raise ValueError("MCQ options must be a JSON list with 2–12 options.")
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

EXAM_HTML=r'''<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Sunrise CTF</title><style>
:root{--bg:#0b1220;--panel:#111c30;--line:#263750;--text:#e8eef8;--muted:#9aaec8;--accent:#58d5b3}*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font:16px/1.5 system-ui,Arial}header{padding:20px max(18px,calc((100vw - 1180px)/2));border-bottom:1px solid var(--line);display:flex;justify-content:space-between;gap:12px;align-items:center;flex-wrap:wrap}h1{margin:0;font-size:clamp(20px,3vw,29px)}header p,.muted{color:var(--muted);font-size:14px}.actions{display:flex;gap:8px;flex-wrap:wrap}button{cursor:pointer}.pill{border:1px solid var(--line);border-radius:99px;padding:7px 11px;font-size:13px}main{max-width:1180px;margin:22px auto;padding:0 16px;display:grid;grid-template-columns:290px 1fr;gap:16px}.panel,.challenge{background:var(--panel);border:1px solid var(--line);border-radius:14px;padding:18px;min-width:0}.stat{font-size:25px;font-weight:750}.progress{height:8px;background:#24334b;border-radius:20px;overflow:hidden;margin:8px 0 16px}.bar{height:100%;background:var(--accent);width:0}nav{display:grid;grid-template-columns:repeat(5,1fr);gap:6px;margin-top:14px}nav button{padding:9px;border:1px solid var(--line);background:#17253b;color:var(--text);border-radius:8px}nav button.done{background:#145b42;border-color:#22a879}nav button.active{outline:2px solid var(--accent)}.tag{display:inline-block;background:#203657;color:#b8d5ff;padding:4px 9px;border-radius:20px;font-size:12px}.prompt{white-space:pre-wrap;overflow-wrap:anywhere;line-height:1.65;margin:18px 0}.answer-option{display:flex;gap:10px;align-items:flex-start;border:1px solid var(--line);border-radius:9px;padding:12px;margin:8px 0}.answer-option input{margin-top:5px}.answer-text{width:100%;padding:12px;border:1px solid #354965;border-radius:9px;background:#09111f;color:#fff;font:inherit}.action{padding:10px 14px;border:0;border-radius:9px;background:var(--accent);color:#08231c;font-weight:750}.secondary{background:#243650;color:var(--text)}.feedback{display:none;margin-top:12px;padding:11px;border-radius:9px}.feedback.good{display:block;background:#123f31;color:#a7f3d0;border:1px solid #18865e}.feedback.bad{display:block;background:#4a1d2a;color:#fecdd3;border:1px solid #a33b55}.notice{padding:10px;border:1px solid #725b28;background:#3d321a;color:#f9e7a5;border-radius:9px;font-size:13px;margin-top:14px}footer{max-width:1180px;margin:auto;padding:0 16px 24px;color:var(--muted);font-size:12px}@media(max-width:800px){main{grid-template-columns:1fr}nav{grid-template-columns:repeat(6,1fr)}}
</style></head><body><header><div><h1>Sunrise Cybersecurity CTF</h1><p>{{level_title}}</p></div><div class="actions"><span class="pill">{{candidate_name}} · {{candidate_id}}</span><span class="pill">Time left: <b id="timer">Loading…</b></span><button class="action secondary" id="logout">Sign out</button></div></header><main><aside class="panel"><div class="muted">CHALLENGES SOLVED</div><div class="stat"><span id="solved">0</span> / <span id="total">0</span></div><div class="progress"><div class="bar" id="bar"></div></div><div class="muted">Score</div><div class="stat"><span id="points">0</span> / <span id="maxpoints">0</span></div><p class="muted">Submit an answer to receive immediate green/red validation. Points are awarded once per challenge.</p><nav id="nav"></nav><div class="notice">Only use assigned training targets and evidence. Do not test unauthorized systems.</div></aside><section class="challenge"><div class="tag" id="category">Loading</div><h2 id="title">Loading challenge…</h2><div class="muted" id="meta"></div><div class="prompt" id="prompt"></div><form id="answerForm"><div id="answerArea"></div><div class="actions" style="margin-top:14px"><button class="action" id="submitBtn" type="submit">Submit answer</button><button class="action secondary" type="button" id="clear">Clear</button><button class="action secondary" type="button" id="next">Next challenge →</button></div></form><div id="feedback" class="feedback" role="status" aria-live="polite"></div><div id="expired" class="notice" style="display:none">Time is up. Answers are saved.</div></section></main><footer>Progress is stored on the exam server. Contact your instructor if you encounter a lab or access issue.</footer>
<script>
const csrf={{csrf|tojson}};let questions=[],current=null,solvedSet=new Set(),deadline=null,timerHandle=null,expired=false;
const nav=document.getElementById('nav');async function api(url,opts={}){opts.headers=Object.assign({'X-CSRF-Token':csrf},opts.headers||{});return fetch(url,opts)}
function feedback(kind,msg){const f=document.getElementById('feedback');f.className='feedback '+kind;f.textContent=msg}
function stats(points,max){document.getElementById('solved').textContent=solvedSet.size;document.getElementById('points').textContent=points;document.getElementById('bar').style.width=(max?points/max*100:0)+'%';document.querySelectorAll('nav button').forEach(b=>b.classList.toggle('done',solvedSet.has(Number(b.dataset.id))))}
function renderTimer(){if(!deadline)return;let n=Math.max(0,Math.floor((deadline-Date.now())/1000));document.getElementById('timer').textContent=[Math.floor(n/3600),Math.floor(n%3600/60),n%60].map(x=>String(x).padStart(2,'0')).join(':');if(n<=0){expired=true;document.getElementById('expired').style.display='block';document.querySelectorAll('#answerArea input,#submitBtn,#clear,#next').forEach(x=>x.disabled=true);clearInterval(timerHandle)}}
function renderAnswer(q){const area=document.getElementById('answerArea');area.replaceChildren();if(q.qtype==='single_choice'||q.qtype==='true_false'){(q.options||[]).forEach((o,i)=>{const label=document.createElement('label');label.className='answer-option';const input=document.createElement('input');input.type='radio';input.name='answer';input.value=o.value;input.required=true;const span=document.createElement('span');span.textContent=o.label;label.append(input,span);area.append(label)})}else if(q.qtype==='multiple_choice'){(q.options||[]).forEach(o=>{const label=document.createElement('label');label.className='answer-option';const input=document.createElement('input');input.type='checkbox';input.name='answer';input.value=o.value;const span=document.createElement('span');span.textContent=o.label;label.append(input,span);area.append(label)})}else{const label=document.createElement('label');label.textContent=q.qtype==='flag'?'Flag answer':'Text answer';label.htmlFor='answerText';const input=document.createElement('input');input.className='answer-text';input.id='answerText';input.name='answer';input.autocomplete='off';input.spellcheck=false;input.maxLength=500;input.required=true;input.placeholder=q.qtype==='flag'?'SUNRISE{your_answer}':'Enter your answer';area.append(label,input)}}
async function load(id){if(expired)return;current=questions.find(q=>q.id===id);if(!current)return;const r=await api('/api/challenge/'+id);if(r.status===401){location.reload();return}const q=await r.json();if(!r.ok){feedback('bad',q.error||'Could not load challenge.');return}document.getElementById('title').textContent=q.title;document.getElementById('category').textContent=q.category;document.getElementById('meta').textContent='Challenge '+(questions.findIndex(x=>x.id===id)+1)+' of '+questions.length+' · '+q.points+' points'+(q.solved?' · SOLVED':'');document.getElementById('prompt').textContent=q.prompt;renderAnswer(q);document.querySelectorAll('nav button').forEach(b=>b.classList.toggle('active',Number(b.dataset.id)===id));if(q.solved)feedback('good','✓ Already solved. Your points are saved.');else{const f=document.getElementById('feedback');f.className='feedback';f.textContent=''}}
async function init(){const r=await api('/api/challenges');if(!r.ok){location.reload();return}const d=await r.json();questions=d.questions;solvedSet=new Set(d.solved);deadline=Date.parse(d.deadline_at);expired=d.expired;document.getElementById('total').textContent=questions.length;document.getElementById('maxpoints').textContent=d.max_points;nav.replaceChildren();questions.forEach((q,i)=>{const b=document.createElement('button');b.type='button';b.textContent=i+1;b.dataset.id=q.id;b.setAttribute('aria-label','Challenge '+(i+1));b.onclick=()=>load(q.id);nav.append(b)});stats(d.points,d.max_points);renderTimer();timerHandle=setInterval(renderTimer,1000);if(expired)document.getElementById('expired').style.display='block';if(questions.length)load(questions[0].id);else document.getElementById('title').textContent='No active challenges. Contact your instructor.'}
document.getElementById('answerForm').onsubmit=async e=>{e.preventDefault();if(expired||!current)return;const q=current;let answer;if(q.qtype==='multiple_choice')answer=[...document.querySelectorAll('input[name="answer"]:checked')].map(x=>x.value);else if(q.qtype==='single_choice'||q.qtype==='true_false')answer=document.querySelector('input[name="answer"]:checked')?.value||'';else answer=document.getElementById('answerText').value;const btn=document.getElementById('submitBtn');btn.disabled=true;try{const r=await api('/api/submit',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({id:q.id,answer})});const d=await r.json();if(r.status===401){location.reload();return}if(r.status===429){feedback('bad',d.error||'Too many attempts.');return}if(d.expired){expired=true;renderTimer();return}if(d.correct){solvedSet.add(q.id);feedback('good','✓ Correct! Your score has been saved.');document.getElementById('meta').textContent='Solved · '+q.points+' points'}else feedback('bad','✕ Incorrect answer. Review the challenge evidence and try again.');stats(d.points,d.max_points)}catch(e){feedback('bad','Network error. Check your connection and retry.')}finally{btn.disabled=expired}};
document.getElementById('clear').onclick=()=>{if(expired)return;document.querySelectorAll('#answerArea input').forEach(x=>{if(x.type==='checkbox'||x.type==='radio')x.checked=false;else x.value=''});const f=document.getElementById('feedback');f.className='feedback';f.textContent=''};document.getElementById('next').onclick=()=>{if(!questions.length)return;const i=questions.findIndex(q=>q.id===current.id);load(questions[(i+1)%questions.length].id)};document.getElementById('logout').onclick=async()=>{await api('/api/logout',{method:'POST'});location.href='/'};init();
</script></body></html>'''

ADMIN_LOGIN=r'''<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Sunrise Staff Login</title><style>body{background:#0b1220;color:#e8eef8;font:16px system-ui;display:grid;place-items:center;min-height:100vh;margin:0;padding:20px}.card{background:#111c30;padding:24px;border:1px solid #263750;border-radius:14px;width:min(100%,440px)}input{width:100%;box-sizing:border-box;padding:12px;margin:8px 0;background:#09111f;color:#fff;border:1px solid #354965;border-radius:8px}button{padding:12px;width:100%;background:#58d5b3;border:0;border-radius:8px;font-weight:bold}.error{color:#fecdd3}.muted{color:#9aaec8;font-size:14px}</style></head><body><div class="card"><h1>Sunrise Staff Login</h1><p class="muted">Use your assigned staff username and password.</p><form method="post"><input type="hidden" name="csrf" value="{{csrf}}"><label>Username</label><input name="username" autocomplete="username" maxlength="80" required><label>Password</label><input type="password" name="password" autocomplete="current-password" required><button>Sign in</button></form>{% if error %}<p class="error">{{error}}</p>{% endif %}</div></body></html>'''

ADMIN_HTML=r'''<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Sunrise Instructor Dashboard</title><style>
body{margin:0;background:#0b1220;color:#e8eef8;font:15px/1.5 system-ui,Arial;padding:20px}main{max-width:1200px;margin:auto}.card{background:#111c30;border:1px solid #263750;border-radius:14px;padding:18px;margin:14px 0}input,select,textarea{padding:10px;background:#09111f;color:#fff;border:1px solid #354965;border-radius:8px;margin:5px;max-width:100%;box-sizing:border-box}button,.btn{padding:10px 14px;border:0;border-radius:8px;background:#58d5b3;color:#08231c;font-weight:bold;cursor:pointer}table{width:100%;border-collapse:collapse}td,th{text-align:left;border-bottom:1px solid #263750;padding:8px;vertical-align:top}.muted{color:#9aaec8}.alert{background:#3d321a;color:#f9e7a5;padding:12px;border-radius:8px}.success{background:#123f31;color:#a7f3d0;padding:12px;border-radius:8px}a{color:#9be8d2}.nav{display:flex;gap:10px;flex-wrap:wrap}.nav a{padding:9px 12px;border:1px solid #263750;border-radius:8px;text-decoration:none}code{overflow-wrap:anywhere}</style></head><body><main>
<h1>Sunrise CTF — Staff Dashboard</h1><p class="muted">Signed in as {{staff.full_name}} · {{role_label}}</p><div class="nav">{% if can_questions %}<a href="/admin/questions">Manage question bank</a><a href="/admin/answer-key.json">Download answer key</a><a href="/admin/questions/export.json">Export question bank</a>{% endif %}{% if can_results %}<a href="/admin/export.csv">Export results CSV</a>{% endif %}{% if can_users %}<a href="/admin/users">Manage users & roles</a>{% endif %}<a href="/admin/logout">Logout</a></div>
<div class="alert">Keep this portal, the private .env file, application source and answer keys away from students. Avoid editing question content during a live exam; changes affect both level portals immediately.</div>
{% if can_students %}<div class="card"><h2>Create candidate student</h2><form method="post" action="/admin/create"><input type="hidden" name="csrf" value="{{csrf}}"><input name="candidate_id" placeholder="Candidate ID (e.g. STU-001)" maxlength="80" required><input name="name" placeholder="Candidate name" maxlength="120" required><label>Exam access</label><label><input type="checkbox" name="allowed_levels" value="level1" checked> Level 1 — Ethical Hacking</label><label><input type="checkbox" name="allowed_levels" value="level2"> Level 2 — Penetration Testing</label><button>Create candidate + PIN</button></form>{% if new_candidate %}<div class="success"><b>Candidate:</b> {{new_candidate.candidate_id}} — {{new_candidate.name}}<br><b>PIN (shown once):</b> <code>{{new_candidate.pin}}</code></div>{% endif %}{% if error %}<p style="color:#fecdd3">{{error}}</p>{% endif %}</div>{% endif %}
{% if can_results %}<div class="card"><h2>Candidate results</h2><table><thead><tr><th>Candidate</th><th>Level 1</th><th>Level 2</th><th>Latest activity</th></tr></thead><tbody>{% for r in results %}<tr><td>{{r.candidate_id}}<br>{{r.name}}</td><td>{{r.l1_solved}} solved · {{r.l1_points}} points{% if r.l1_deadline %}<br><span class="muted">Deadline {{r.l1_deadline}}</span>{% endif %}</td><td>{{r.l2_solved}} solved · {{r.l2_points}} points{% if r.l2_deadline %}<br><span class="muted">Deadline {{r.l2_deadline}}</span>{% endif %}</td><td>{{r.last_activity or 'No submissions'}}</td></tr>{% endfor %}</tbody></table></div>{% endif %}
{% if can_questions %}<div class="card"><h2>Question bank summary</h2><p>Level 1: <b>{{l1_count}}</b> active / {{l1_all}} total questions. Level 2: <b>{{l2_count}}</b> active / {{l2_all}} total questions.</p><p>Supported types: flag, short text, single-choice MCQ, multiple-choice MCQ, and true/false.</p><a class="btn" href="/admin/questions">Add or modify questions</a></div>{% endif %}</main></body></html>'''

QUESTION_ADMIN=r'''<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Manage Questions</title><style>
body{margin:0;background:#0b1220;color:#e8eef8;font:15px/1.5 system-ui,Arial;padding:20px}main{max-width:1300px;margin:auto}.card{background:#111c30;border:1px solid #263750;border-radius:14px;padding:18px;margin:14px 0}input,select,textarea{width:100%;box-sizing:border-box;padding:10px;background:#09111f;color:#fff;border:1px solid #354965;border-radius:8px;margin:5px 0 12px;font:inherit}textarea{min-height:90px}label{display:block;color:#c8d5e8;font-size:14px}button,.btn{padding:10px 14px;border:0;border-radius:8px;background:#58d5b3;color:#08231c;font-weight:bold;cursor:pointer}button.danger{background:#b83350;color:#fff}table{width:100%;border-collapse:collapse}td,th{text-align:left;border-bottom:1px solid #263750;padding:8px;vertical-align:top}.muted{color:#9aaec8}.alert{background:#3d321a;color:#f9e7a5;padding:12px;border-radius:8px}.error{background:#4a1d2a;color:#fecdd3;padding:12px;border-radius:8px}.success{background:#123f31;color:#a7f3d0;padding:12px;border-radius:8px}.grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:12px}.actions{display:flex;gap:8px;align-items:center;flex-wrap:wrap}a{color:#9be8d2}.small{font-size:12px;color:#9aaec8}@media(max-width:760px){.grid{grid-template-columns:1fr}table{font-size:13px}}
</style></head><body><main><h1>Question Bank Management</h1><p><a href="/admin">← Instructor dashboard</a> · <a href="/admin/logout">Logout</a></p><div class="alert">Changes take effect immediately on both portals. Do not edit or delete questions while students are sitting the exam. Back up the database before bulk changes.</div>{% if message %}<div class="success">{{message}}</div>{% endif %}{% if error %}<div class="error">{{error}}</div>{% endif %}
<div class="card"><h2>{% if edit %}Edit question #{{edit.id}}{% else %}Add a question{% endif %}</h2><form method="post" action="/admin/questions/save"><input type="hidden" name="csrf" value="{{csrf}}"><input type="hidden" name="id" value="{{edit.id if edit else ''}}"><div class="grid"><div><label>Level</label><select name="level" {% if edit %}disabled{% endif %}><option value="level1" {% if not edit or edit.level=='level1' %}selected{% endif %}>Level 1 — Ethical Hacking</option><option value="level2" {% if edit and edit.level=='level2' %}selected{% endif %}>Level 2 — Penetration Testing</option></select>{% if edit %}<input type="hidden" name="level" value="{{edit.level}}">{% endif %}</div><div><label>Question type</label><select name="qtype" id="qtype" onchange="showHelp()"><option value="flag" {% if edit and edit.qtype=='flag' %}selected{% endif %}>Flag-based</option><option value="short_text" {% if edit and edit.qtype=='short_text' %}selected{% endif %}>Short text</option><option value="single_choice" {% if edit and edit.qtype=='single_choice' %}selected{% endif %}>Single-choice MCQ</option><option value="multiple_choice" {% if edit and edit.qtype=='multiple_choice' %}selected{% endif %}>Multiple-choice MCQ</option><option value="true_false" {% if edit and edit.qtype=='true_false' %}selected{% endif %}>True / False</option></select></div><div><label>Title</label><input name="title" required maxlength="160" value="{{edit.title if edit else ''}}" placeholder="Challenge title"></div><div><label>Category / topic</label><input name="category" maxlength="100" value="{{edit.category if edit else 'General'}}" placeholder="e.g. XSS"></div><div><label>Points (1–10,000)</label><input type="number" name="points" min="1" max="10000" required value="{{edit.points if edit else 100}}"></div><div><label>Availability</label><select name="active"><option value="1" {% if not edit or edit.active %}selected{% endif %}>Active — visible to students</option><option value="0" {% if edit and not edit.active %}selected{% endif %}>Draft / inactive</option></select></div></div><label>Scenario / question instructions</label><textarea name="prompt" required maxlength="12000" placeholder="Write a self-contained challenge, including evidence or target instructions.">{{edit.prompt if edit else ''}}</textarea><div id="optionsWrap"><label>Options JSON (MCQ only)</label><textarea name="options_json" id="options_json" spellcheck="false">{{options_json}}</textarea><div class="small">Example: [{&quot;value&quot;:&quot;A&quot;,&quot;label&quot;:&quot;Option A&quot;},{&quot;value&quot;:&quot;B&quot;,&quot;label&quot;:&quot;Option B&quot;}]</div></div><label>Correct answer / accepted answer(s)</label><textarea name="answer" required spellcheck="false" placeholder="Flag: SUNRISE{answer}; MCQ: option value A; multi-choice: A,C; short text: one accepted answer per line; true/false: true or false">{{edit_answer}}</textarea><div id="help" class="small">Flag: enter the exact expected flag. Short text: one accepted answer per line. MCQ options are JSON. Multiple-choice correct values are comma-separated. True/False: enter true or false.</div><div class="actions"><button type="submit">{% if edit %}Save changes{% else %}Add question{% endif %}</button><a class="btn" href="/admin/questions">Clear / new question</a></div></form></div>
<div class="card"><h2>Existing questions ({{questions|length}})</h2><form method="get"><label>Filter by level</label><select name="level" onchange="this.form.submit()"><option value="all" {% if level_filter=='all' %}selected{% endif %}>Both levels</option><option value="level1" {% if level_filter=='level1' %}selected{% endif %}>Level 1</option><option value="level2" {% if level_filter=='level2' %}selected{% endif %}>Level 2</option></select></form><div style="overflow-x:auto"><table><thead><tr><th>ID</th><th>Level</th><th>Question</th><th>Type</th><th>Points</th><th>Status</th><th>Actions</th></tr></thead><tbody>{% for q in questions %}<tr><td>{{q.id}}</td><td>{{q.level}}</td><td><b>{{q.title}}</b><br><span class="muted">{{q.category}}</span></td><td>{{q.qtype}}</td><td>{{q.points}}</td><td>{{'Active' if q.active else 'Draft'}}</td><td><div class="actions"><a class="btn" href="/admin/questions?edit={{q.id}}&level={{level_filter}}">Edit</a><form method="post" action="/admin/questions/delete" onsubmit="return confirm('Delete this question? This cannot be undone.');"><input type="hidden" name="csrf" value="{{csrf}}"><input type="hidden" name="id" value="{{q.id}}"><button class="danger">Delete</button></form></div></td></tr>{% endfor %}</tbody></table></div></div></main><script>function showHelp(){const t=document.getElementById('qtype').value;document.getElementById('optionsWrap').style.display=['single_choice','multiple_choice'].includes(t)?'block':'none';const help={flag:'Enter the expected flag exactly. Student answers are trimmed and compared case-insensitively.',short_text:'Enter accepted answers one per line. Matching ignores surrounding whitespace and letter case.',single_choice:'Options JSON is a list of value/label objects. Correct answer must be one option value.',multiple_choice:'Options JSON is a list of value/label objects. Enter all correct option values separated by commas, e.g. A,C.',true_false:'Enter true or false. Options are generated automatically.'};document.getElementById('help').textContent=help[t]}showHelp();</script></body></html>'''

@app.get('/')
def index():
    if session.get('staff_user_id'): return redirect('/admin')
    cid=session.get('candidate_id')
    if not cid or not candidate_info(cid): return render_template_string(LOGIN_HTML,csrf=csrf_token(),level_title=LEVEL_TITLES[LEVEL])
    ci=candidate_info(cid)
    return render_template_string(EXAM_HTML,csrf=csrf_token(),level_title=LEVEL_TITLES[LEVEL],candidate_name=ci['name'],candidate_id=ci['candidate_id'])

@app.post('/api/login')
def login():
    if not check_csrf(): return jsonify({'error':'Session expired. Refresh and try again.'}),400
    body=request.get_json(silent=True) or {}; cid=str(body.get('candidate_id','')).strip(); pin=str(body.get('pin','')).strip()
    if not cid or not pin or len(cid)>80 or len(pin)>80: return jsonify({'error':'Enter candidate ID and PIN.'}),400
    with db() as con: row=con.execute('SELECT candidate_id,name,pin_salt,pin_hash,active,allowed_levels FROM candidates WHERE candidate_id=?',(cid,)).fetchone()
    if not row or not row['active'] or not hmac.compare_digest(pin_hash(pin,row['pin_salt']),row['pin_hash']):
        time.sleep(0.25); return jsonify({'error':'Candidate ID or PIN is incorrect.'}),401
    if LEVEL not in (row['allowed_levels'] or '').split(','):
        time.sleep(0.15); return jsonify({'error':'You are not assigned to this exam level. Contact the exam administrator.'}),403
    session.clear(); session['candidate_id']=row['candidate_id']; session['csrf']=secrets.token_urlsafe(24); session.permanent=True
    return jsonify({'ok':True})

@app.post('/api/logout')
def logout():
    if not check_csrf(): return jsonify({'error':'Invalid request.'}),400
    session.clear(); return jsonify({'ok':True})

@app.get('/api/challenges')
@student_required
def list_challenges():
    cid=session['candidate_id']; status=exam_status(cid,start=True); questions=get_questions(LEVEL)
    with db() as con:
        solved_rows=con.execute('SELECT s.challenge_id,q.points AS points FROM solves s JOIN questions q ON q.id=s.challenge_id AND q.level=s.level WHERE s.candidate_id=? AND s.level=? AND q.active=1',(cid,LEVEL)).fetchall()
    solved=[r['challenge_id'] for r in solved_rows]; points=sum(int(r['points']) for r in solved_rows); max_points=sum(int(q['points']) for q in questions)
    return jsonify({'questions':[{'id':q['id'],'title':q['title'],'qtype':q['qtype'],'points':q['points']} for q in questions], 'total':len(questions),'solved':solved,'points':points,'max_points':max_points,'deadline_at':status['deadline_at'],'expired':status['expired']})

@app.get('/api/challenge/<int:question_id>')
@student_required
def get_challenge(question_id):
    status=exam_status(session['candidate_id'],start=True)
    if status['expired']: return jsonify({'expired':True,'error':'Exam time has ended.'}),403
    q=get_question(question_id)
    if not q: return jsonify({'error':'Challenge not found.'}),404
    with db() as con: solved=con.execute('SELECT 1 FROM solves WHERE candidate_id=? AND level=? AND challenge_id=?',(session['candidate_id'],LEVEL,question_id)).fetchone() is not None
    return jsonify(public_question(q,solved))

@app.post('/api/submit')
@student_required
def submit():
    if not check_csrf(): return jsonify({'error':'Invalid request token. Refresh the page.'}),400
    body=request.get_json(silent=True) or {}
    try: qid=int(body.get('id',0))
    except (TypeError,ValueError): return jsonify({'error':'Invalid question.'}),400
    q=get_question(qid)
    if not q: return jsonify({'error':'Question not found or inactive.'}),400
    status=exam_status(session['candidate_id'],start=True)
    if status['expired']: return jsonify({'expired':True,'correct':False,'error':'Exam time has ended.'}),403
    cid=session['candidate_id']; now=utcnow()
    with db() as con:
        recent=con.execute('SELECT COUNT(*) n FROM submissions WHERE candidate_id=? AND level=? AND submitted_at>=?',(cid,LEVEL,iso(now-timedelta(seconds=60)))).fetchone()['n']
        if recent>=30: return jsonify({'error':'Rate limit reached. Wait before trying again.'}),429
        answer=body.get('answer',body.get('flag',''))
        correct=answers_match(q,answer)
        con.execute('INSERT INTO submissions(candidate_id,level,challenge_id,correct,submitted_at) VALUES(?,?,?,?,?)',(cid,LEVEL,qid,1 if correct else 0,iso(now)))
        if correct: con.execute('INSERT OR IGNORE INTO solves(candidate_id,level,challenge_id,points,solved_at) VALUES(?,?,?,?,?)',(cid,LEVEL,qid,q['points'],iso(now)))
        rows=con.execute('SELECT s.challenge_id,q.points AS points FROM solves s JOIN questions q ON q.id=s.challenge_id AND q.level=s.level WHERE s.candidate_id=? AND s.level=? AND q.active=1',(cid,LEVEL)).fetchall()
        points=sum(r['points'] for r in rows); max_points=con.execute('SELECT COALESCE(SUM(points),0) n FROM questions WHERE level=? AND active=1',(LEVEL,)).fetchone()['n']
    return jsonify({'correct':correct,'expired':False,'points':points,'max_points':max_points})

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
                stats=con.execute('SELECT COUNT(*) n,COALESCE(SUM(s.points),0) pts FROM solves s JOIN questions q ON q.id=s.challenge_id AND q.level=s.level WHERE s.candidate_id=? AND s.level=? AND q.active=1',(c['candidate_id'],lev)).fetchone()
                sess=con.execute('SELECT deadline_at FROM exam_sessions WHERE candidate_id=? AND level=?',(c['candidate_id'],lev)).fetchone()
                row[prefix+'_solved']=stats['n']; row[prefix+'_points']=stats['pts']; row[prefix+'_deadline']=sess['deadline_at'] if sess else None
            row['last_activity']=con.execute('SELECT MAX(submitted_at) t FROM submissions WHERE candidate_id=?',(c['candidate_id'],)).fetchone()['t']; results.append(row)
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
    filt=request.args.get('level','all'); edit_id=request.args.get('edit',type=int); edit=None; edit_answer=''; options_json='[]'
    with db() as con:
        if edit_id:
            r=con.execute('SELECT * FROM questions WHERE id=?',(edit_id,)).fetchone()
            if r:
                edit=dict(r); options_json=json.dumps(json.loads(edit['options_json'] or '[]'),ensure_ascii=False,indent=2); ans=json.loads(edit['answer_json'])
                edit_answer=(','.join(map(str,ans)) if edit['qtype']=='multiple_choice' else '\n'.join(map(str,ans))) if isinstance(ans,list) else str(ans)
        if filt in ('level1','level2'): rows=con.execute('SELECT * FROM questions WHERE level=? ORDER BY level,id',(filt,)).fetchall()
        else: rows=con.execute('SELECT * FROM questions ORDER BY level,id').fetchall(); filt='all'
    qs=[dict(r) for r in rows]
    return render_template_string(QUESTION_ADMIN,csrf=csrf_token(),questions=qs,edit=edit,edit_answer=edit_answer,options_json=options_json,level_filter=filt,message=request.args.get('message'),error=request.args.get('error'))

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
    out=io.StringIO(); w=csv.writer(out); w.writerow(['candidate_id','name','level1_solved','level1_points','level2_solved','level2_points','latest_activity'])
    for r in admin_results(): w.writerow([r['candidate_id'],r['name'],r['l1_solved'],r['l1_points'],r['l2_solved'],r['l2_points'],r['last_activity'] or ''])
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
@permission_required('manage_students')
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

@app.post('/admin/users/student-pin')
@permission_required('manage_students')
def admin_student_pin():
    if not check_csrf(request.form.get('csrf')):
        return redirect('/admin/users?error=Session+expired')
    cid=request.form.get('candidate_id','').strip()
    pin=request.form.get('new_pin','')
    if not cid or len(pin)<4 or len(pin)>80:
        return redirect('/admin/users?error=Student+PIN+must+be+4+to+80+characters')
    salt=secrets.token_hex(16)
    with db() as con:
        cur=con.execute('UPDATE candidates SET pin_salt=?,pin_hash=? WHERE candidate_id=?',
                        (salt,pin_hash(pin,salt),cid))
        if cur.rowcount==0:
            return redirect('/admin/users?error=Student+not+found')
    audit('reset_student_pin',cid,'Student PIN reset by authorized staff')
    return redirect('/admin/users?message=Student+PIN+updated')

@app.post('/admin/users/student-status')
@permission_required('manage_students')
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
def health():
    try:
        with db() as con:
            con.execute('SELECT 1'); n=con.execute('SELECT COUNT(*) n FROM questions WHERE level=? AND active=1',(LEVEL,)).fetchone()['n']
        return jsonify({'status':'ok','level':LEVEL,'active_questions':n})
    except Exception: return jsonify({'status':'error'}),500

if __name__=='__main__': app.run(host='0.0.0.0',port=PORT,debug=False)
