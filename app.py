import os, sqlite3, uuid, hashlib, hmac, json, secrets, mimetypes
from datetime import datetime, timezone
from functools import wraps
from pathlib import Path
from flask import Flask, request, redirect, url_for, session, flash, send_file, abort, render_template_string, g
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

BASE = Path(__file__).resolve().parent
DATA_DIR = Path(os.environ.get("TRUSTVAULT_DATA", BASE / "private_uploads")).resolve()
DATA_DIR.mkdir(parents=True, exist_ok=True)
DB_PATH = Path(os.environ.get("TRUSTVAULT_DB", BASE / "trustvault.sqlite3"))
SECRET_KEY = os.environ.get("TRUSTVAULT_SECRET", "dev-only-change-this-secret-before-deployment")
AUDIT_KEY = os.environ.get("TRUSTVAULT_AUDIT_KEY", "dev-only-change-this-audit-key-before-deployment").encode()
MAX_BYTES = 10 * 1024 * 1024
ALLOWED = {".pdf", ".png", ".jpg", ".jpeg", ".txt"}
app = Flask(__name__)
app.secret_key = SECRET_KEY
app.config["MAX_CONTENT_LENGTH"] = MAX_BYTES
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = os.environ.get("COOKIE_SECURE", "0") == "1"

def now():
    return datetime.now(timezone.utc).isoformat()

def db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys=ON")
    return g.db

@app.teardown_appcontext
def close_db(_=None):
    conn = g.pop("db", None)
    if conn: conn.close()

def init_db():
    conn = sqlite3.connect(DB_PATH)
    conn.executescript("""
    PRAGMA foreign_keys=ON;
    CREATE TABLE IF NOT EXISTS users(
      id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL, role TEXT NOT NULL CHECK(role IN ('admin','owner','viewer')),
      active INTEGER NOT NULL DEFAULT 1, created_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS documents(
      id TEXT PRIMARY KEY, original_name TEXT NOT NULL, stored_name TEXT NOT NULL UNIQUE,
      owner_id INTEGER NOT NULL REFERENCES users(id), category TEXT NOT NULL,
      mime TEXT NOT NULL, size INTEGER NOT NULL, sha256 TEXT NOT NULL,
      created_at TEXT NOT NULL, updated_at TEXT NOT NULL, deleted INTEGER NOT NULL DEFAULT 0
    );
    CREATE TABLE IF NOT EXISTS grants(
      id INTEGER PRIMARY KEY AUTOINCREMENT, document_id TEXT NOT NULL REFERENCES documents(id),
      user_id INTEGER NOT NULL REFERENCES users(id), permission TEXT NOT NULL CHECK(permission IN ('read','edit')),
      granted_by INTEGER NOT NULL REFERENCES users(id), created_at TEXT NOT NULL,
      UNIQUE(document_id,user_id)
    );
    CREATE TABLE IF NOT EXISTS audit(
      id INTEGER PRIMARY KEY AUTOINCREMENT, at TEXT NOT NULL, actor_id INTEGER,
      actor_name TEXT NOT NULL, action TEXT NOT NULL, document_id TEXT,
      details TEXT NOT NULL, previous_hash TEXT NOT NULL, entry_hash TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_docs_owner ON documents(owner_id);
    CREATE INDEX IF NOT EXISTS idx_grants_user ON grants(user_id,document_id);
    CREATE INDEX IF NOT EXISTS idx_audit_doc ON audit(document_id,id);
    """)
    conn.commit(); conn.close()

def audit(actor_id, actor_name, action, document_id=None, details=None):
    conn = db()
    last = conn.execute("SELECT entry_hash FROM audit ORDER BY id DESC LIMIT 1").fetchone()
    prev = last["entry_hash"] if last else "GENESIS"
    at = now()
    payload = json.dumps({"at":at,"actor_id":actor_id,"actor_name":actor_name,
        "action":action,"document_id":document_id,"details":details or {}},
        sort_keys=True, separators=(",",":"))
    digest = hmac.new(AUDIT_KEY, (prev + payload).encode(), hashlib.sha256).hexdigest()
    conn.execute("""INSERT INTO audit(at,actor_id,actor_name,action,document_id,details,previous_hash,entry_hash)
                    VALUES(?,?,?,?,?,?,?,?)""",
                 (at,actor_id,actor_name,action,document_id,json.dumps(details or {}),prev,digest))
    conn.commit()

def current_user():
    if not session.get("uid"): return None
    return db().execute("SELECT * FROM users WHERE id=? AND active=1",(session["uid"],)).fetchone()

def login_required(fn):
    @wraps(fn)
    def wrapped(*a, **kw):
        if not current_user(): return redirect(url_for("login"))
        return fn(*a, **kw)
    return wrapped

def role_required(*roles):
    def deco(fn):
        @wraps(fn)
        def wrapped(*a, **kw):
            u=current_user()
            if not u: return redirect(url_for("login"))
            if u["role"] not in roles: abort(403)
            return fn(*a, **kw)
        return wrapped
    return deco

def can_read(doc_id, user):
    row=db().execute("""SELECT d.*, u.username owner_name FROM documents d
        JOIN users u ON u.id=d.owner_id WHERE d.id=? AND d.deleted=0""",(doc_id,)).fetchone()
    if not row: return None
    grant=db().execute("SELECT permission FROM grants WHERE document_id=? AND user_id=?",(doc_id,user["id"])).fetchone()
    if row["owner_id"] == user["id"] or (grant and grant["permission"] in ("read","edit")):
        return row
    return None

def can_edit(doc_id,user):
    row=can_read(doc_id,user)
    if not row: return None
    if row["owner_id"] == user["id"]: return row
    grant=db().execute("SELECT permission FROM grants WHERE document_id=? AND user_id=?",(doc_id,user["id"])).fetchone()
    return row if grant and grant["permission"]=="edit" else None

def csrf():
    token=session.get("_csrf")
    if not token:
        token=secrets.token_urlsafe(32); session["_csrf"]=token
    return token

@app.before_request
def csrf_protect():
    if request.method=="POST":
        token=request.form.get("_csrf","")
        if not token or not hmac.compare_digest(token,session.get("_csrf","")):
            abort(400, "CSRF validation failed")

@app.context_processor
def inject():
    return {"me":current_user(),"csrf_token":csrf}

@app.errorhandler(403)
def forbidden(e): return render_template_string(BASE_HTML, title="Forbidden", body="<h2>403 — Access denied</h2><p>This action is not permitted.</p>"),403
@app.errorhandler(404)
def missing(e): return render_template_string(BASE_HTML, title="Not found", body="<h2>404 — Not found</h2>"),404
@app.errorhandler(413)
def too_large(e): return render_template_string(BASE_HTML, title="Too large", body="<h2>File too large</h2><p>Maximum upload size is 10 MB.</p>"),413

BASE_HTML = """
<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{{title}} · TrustVault</title><style>
body{font-family:Arial,sans-serif;background:#f3f5f8;color:#202938;margin:0}header{background:#18263b;color:white;padding:16px 5%;display:flex;justify-content:space-between;align-items:center}
main{max-width:1050px;margin:28px auto;padding:0 16px}.card{background:white;border:1px solid #e0e5ec;border-radius:10px;padding:18px;margin:14px 0;box-shadow:0 2px 8px #1420330b}
a{color:#1459a6}input,select{padding:9px;border:1px solid #bbc5d2;border-radius:5px;margin:4px}button,.btn{background:#1459a6;color:white;border:0;border-radius:5px;padding:9px 13px;cursor:pointer;text-decoration:none}
table{border-collapse:collapse;width:100%;background:white}td,th{text-align:left;padding:10px;border-bottom:1px solid #e4e8ee}small,.muted{color:#667085}.danger{color:#a22}.row{display:flex;gap:10px;flex-wrap:wrap;align-items:center}
.flash{background:#fff2cc;padding:10px;border-radius:5px;margin:8px 0}code{overflow-wrap:anywhere}
</style></head><body><header><strong>🔐 TrustVault</strong><nav>{% if me %}{{me.username}} ({{me.role}}) · <a style="color:white" href="{{url_for('dashboard')}}">Documents</a> · {% if is_admin %}<a style="color:white" href="{{url_for('admin')}}">Admin</a> · <a style="color:white" href="{{url_for('users_admin')}}">Users</a> · {% endif %}<a style="color:white" href="{{url_for('logout')}}">Logout</a>{% endif %}</nav></header>
<main>{% with msgs=get_flashed_messages() %}{% for m in msgs %}<div class="flash">{{m}}</div>{% endfor %}{% endwith %}{{body|safe}}</main></body></html>
"""

def page(title, body, **ctx):
    return render_template_string(BASE_HTML, title=title, body=render_template_string(body, **ctx))

@app.route("/")
def index(): return redirect(url_for("dashboard") if current_user() else url_for("login"))

@app.route("/login", methods=["GET","POST"])
def login():
    if request.method=="POST":
        name=request.form.get("username","").strip()
        u=db().execute("SELECT * FROM users WHERE username=?",(name,)).fetchone()
        if u and u["active"] and check_password_hash(u["password_hash"],request.form.get("password","")):
            session.clear(); session["uid"]=u["id"]; csrf()
            audit(u["id"],u["username"],"LOGIN_SUCCESS")
            return redirect(url_for("dashboard"))
        audit(u["id"] if u else None,name or "unknown","LOGIN_FAILED",details={"username":name})
        flash("Invalid username or password.")
    return page("Login", """<div class=card style="max-width:420px;margin:50px auto"><h2>Sign in</h2>
    <form method=post><input type=hidden name=_csrf value="{{csrf_token()}}">
    <p><input name=username placeholder="Username" required></p><p><input name=password type=password placeholder="Password" required></p>
    <button>Sign in</button></form><p class=muted>Demo accounts are listed in README.md.</p></div>""")

@app.route("/logout")
@login_required
def logout():
    u=current_user(); audit(u["id"],u["username"],"LOGOUT")
    session.clear(); return redirect(url_for("login"))

@app.route("/dashboard")
@login_required
def dashboard():
    u=current_user()
    q=request.args.get("q","").strip(); category=request.args.get("category","").strip()
    sql="""SELECT DISTINCT d.*,u.username owner_name FROM documents d JOIN users u ON u.id=d.owner_id
      LEFT JOIN grants g ON g.document_id=d.id AND g.user_id=? WHERE d.deleted=0
      AND (d.owner_id=? OR g.user_id=?)"""
    args=[u["id"],u["id"],u["id"]]
    if q: sql+=" AND (d.original_name LIKE ? OR u.username LIKE ? OR d.category LIKE ?)"; args += [f"%{q}%"]*3
    if category: sql+=" AND d.category=?"; args.append(category)
    sql+=" ORDER BY d.created_at DESC"
    docs=db().execute(sql,args).fetchall()
    cats=db().execute("SELECT DISTINCT category FROM documents WHERE deleted=0 ORDER BY category").fetchall()
    body="""<h1>My accessible documents</h1><div class=card><form class=row method=get>
    <input name=q placeholder="Search name, owner or category" value="{{q}}">
    <select name=category><option value="">All categories</option>{% for c in cats %}<option {% if category==c.category %}selected{% endif %}>{{c.category}}</option>{% endfor %}</select><button>Search</button></form></div>
    {% if me.role in ['owner','admin'] %}<div class=card><h3>Upload a document</h3><form method=post action="{{url_for('upload')}}" enctype=multipart/form-data>
    <input type=hidden name=_csrf value="{{csrf_token()}}"><input type=file name=file required><input name=category placeholder="Category" required><button>Upload</button></form><small>PDF, PNG, JPG/JPEG or TXT · max 10 MB</small></div>{% endif %}
    <div class=card><table><tr><th>Document</th><th>Owner</th><th>Category</th><th>Updated</th><th>Actions</th></tr>
    {% for d in docs %}<tr><td>{{d.original_name}}</td><td>{{d.owner_name}}</td><td>{{d.category}}</td><td>{{d.updated_at[:10]}}</td><td>
    <a href="{{url_for('download',doc_id=d.id)}}">Download</a> · <a href="{{url_for('details',doc_id=d.id)}}">Manage</a></td></tr>{% else %}<tr><td colspan=5>No accessible documents yet.</td></tr>{% endfor %}</table></div>"""
    return page("Documents",body,docs=docs,q=q,category=category,cats=cats)

def validate_file(file):
    name=secure_filename(file.filename or "")
    ext=Path(name).suffix.lower()
    if not name or ext not in ALLOWED: return None,"Unsupported file type."
    data=file.read(MAX_BYTES+1); file.seek(0)
    if not data or len(data)>MAX_BYTES: return None,"Empty file or file exceeds 10 MB."
    valid = (ext==".pdf" and data.startswith(b"%PDF-")) or (ext==".png" and data.startswith(b"\x89PNG\r\n\x1a\n")) or (ext in (".jpg",".jpeg") and data.startswith(b"\\xff\\xd8\\xff")) or (ext==".txt" and b"\x00" not in data)
    if not valid: return None,"File content does not match its extension."
    return (name,data),None

@app.route("/upload",methods=["POST"])
@login_required
@role_required("owner","admin")
def upload():
    u=current_user(); f=request.files.get("file"); category=request.form.get("category","").strip()[:80]
    if not f or not category: flash("Choose a file and category."); return redirect(url_for("dashboard"))
    parsed,error=validate_file(f)
    if error: flash(error); return redirect(url_for("dashboard"))
    name,data=parsed; doc_id=str(uuid.uuid4()); stored=uuid.uuid4().hex
    (DATA_DIR/stored).write_bytes(data)
    digest=hashlib.sha256(data).hexdigest(); mime=mimetypes.guess_type(name)[0] or "application/octet-stream"
    db().execute("""INSERT INTO documents(id,original_name,stored_name,owner_id,category,mime,size,sha256,created_at,updated_at)
      VALUES(?,?,?,?,?,?,?,?,?,?)""",(doc_id,name,stored,u["id"],category,mime,len(data),digest,now(),now()))
    db().commit(); audit(u["id"],u["username"],"UPLOAD",doc_id,{"name":name,"sha256":digest,"size":len(data)})
    flash("Document uploaded."); return redirect(url_for("details",doc_id=doc_id))

@app.route("/document/<doc_id>")
@login_required
def details(doc_id):
    u=current_user(); d=can_read(doc_id,u)
    if not d:
        audit(u["id"],u["username"],"ACCESS_DENIED",doc_id,{"operation":"view_details"})
        abort(404)
    is_owner=d["owner_id"]==u["id"]
    grant=db().execute("""SELECT g.*,u.username FROM grants g JOIN users u ON u.id=g.user_id
      WHERE g.document_id=? ORDER BY u.username""",(doc_id,)).fetchall() if is_owner else []
    users=db().execute("SELECT id,username,role FROM users WHERE active=1 AND id<>? ORDER BY username",(d["owner_id"],)).fetchall() if is_owner else []
    body="""<h1>{{d.original_name}}</h1><div class=card><p><b>Owner:</b> {{d.owner_name}} · <b>Category:</b> {{d.category}}</p>
    <p><b>Size:</b> {{d.size}} bytes · <b>SHA-256:</b> <code>{{d.sha256}}</code></p><a class=btn href="{{url_for('download',doc_id=d.id)}}">Download</a></div>
    {% if is_owner %}<div class=card><h3>Grant or change access</h3><form method=post action="{{url_for('grant',doc_id=d.id)}}">
    <input type=hidden name=_csrf value="{{csrf_token()}}"><select name=user_id required>{% for x in users %}<option value="{{x.id}}">{{x.username}} ({{x.role}})</option>{% endfor %}</select>
    <select name=permission><option value=read>Read</option><option value=edit>Edit</option></select><button>Save permission</button></form>
    <h3>Current grants</h3><table><tr><th>User</th><th>Permission</th><th>Action</th></tr>{% for g in grants %}<tr><td>{{g.username}}</td><td>{{g.permission}}</td><td><form method=post action="{{url_for('revoke',doc_id=d.id)}}" style="display:inline"><input type=hidden name=_csrf value="{{csrf_token()}}"><input type=hidden name=user_id value="{{g.user_id}}"><button class=danger>Revoke</button></form></td></tr>{% else %}<tr><td colspan=3>No grants.</td></tr>{% endfor %}</table>
    <form method=post action="{{url_for('delete_doc',doc_id=d.id)}}" onsubmit="return confirm('Delete this document?')"><input type=hidden name=_csrf value="{{csrf_token()}}"><button class=danger>Delete document</button></form></div>{% endif %}"""
    return page("Document",body,d=d,is_owner=is_owner,grants=grant,users=users)

@app.route("/document/<doc_id>/download")
@login_required
def download(doc_id):
    u=current_user(); d=can_read(doc_id,u)
    if not d:
        audit(u["id"],u["username"],"ACCESS_DENIED",doc_id,{"operation":"download"})
        abort(404)
    path=DATA_DIR/d["stored_name"]
    if not path.is_file():
        audit(u["id"],u["username"],"DOWNLOAD_MISSING",doc_id)
        abort(404)
    audit(u["id"],u["username"],"DOWNLOAD",doc_id,{"sha256":d["sha256"]})
    return send_file(path,as_attachment=True,download_name=d["original_name"],mimetype=d["mime"],conditional=True)

@app.route("/document/<doc_id>/grant",methods=["POST"])
@login_required
def grant(doc_id):
    u=current_user(); d=db().execute("SELECT * FROM documents WHERE id=? AND deleted=0",(doc_id,)).fetchone()
    if not d or d["owner_id"]!=u["id"]: abort(403)
    try: uid=int(request.form.get("user_id")); perm=request.form.get("permission")
    except: abort(400)
    target=db().execute("SELECT * FROM users WHERE id=? AND active=1",(uid,)).fetchone()
    if not target or uid==u["id"] or perm not in ("read","edit"): abort(400)
    db().execute("""INSERT INTO grants(document_id,user_id,permission,granted_by,created_at) VALUES(?,?,?,?,?)
      ON CONFLICT(document_id,user_id) DO UPDATE SET permission=excluded.permission,granted_by=excluded.granted_by,created_at=excluded.created_at""",
      (doc_id,uid,perm,u["id"],now())); db().commit()
    audit(u["id"],u["username"],"PERMISSION_GRANTED",doc_id,{"user":target["username"],"permission":perm})
    flash("Permission saved."); return redirect(url_for("details",doc_id=doc_id))

@app.route("/document/<doc_id>/revoke",methods=["POST"])
@login_required
def revoke(doc_id):
    u=current_user(); d=db().execute("SELECT * FROM documents WHERE id=? AND deleted=0",(doc_id,)).fetchone()
    if not d or d["owner_id"]!=u["id"]: abort(403)
    uid=int(request.form.get("user_id","0"))
    target=db().execute("SELECT username FROM users WHERE id=?",(uid,)).fetchone()
    db().execute("DELETE FROM grants WHERE document_id=? AND user_id=?",(doc_id,uid)); db().commit()
    audit(u["id"],u["username"],"PERMISSION_REVOKED",doc_id,{"user":target["username"] if target else str(uid)})
    flash("Access revoked immediately for future requests."); return redirect(url_for("details",doc_id=doc_id))

@app.route("/document/<doc_id>/delete",methods=["POST"])
@login_required
def delete_doc(doc_id):
    u=current_user(); d=db().execute("SELECT * FROM documents WHERE id=? AND deleted=0",(doc_id,)).fetchone()
    if not d or d["owner_id"]!=u["id"]: abort(403)
    db().execute("UPDATE documents SET deleted=1,updated_at=? WHERE id=?",(now(),doc_id))
    db().execute("DELETE FROM grants WHERE document_id=?",(doc_id,)); db().commit()
    audit(u["id"],u["username"],"DELETE",doc_id,{"name":d["original_name"]})
    flash("Document deleted (soft delete)."); return redirect(url_for("dashboard"))

@app.route("/admin")
@login_required
@role_required("admin")
def admin():
    logs=db().execute("SELECT * FROM audit ORDER BY id DESC LIMIT 300").fetchall()
    docs=db().execute("SELECT COUNT(*) n FROM documents WHERE deleted=0").fetchone()["n"]
    users=db().execute("SELECT id,username,role,active FROM users ORDER BY username").fetchall()
    body="""<h1>Administrator console</h1><div class=card><b>Active documents:</b> {{docs}} · <b>Accounts:</b> {{users|length}}</div>
    <div class=card><h3>Users</h3><table><tr><th>Username</th><th>Role</th><th>Active</th></tr>{% for x in users %}<tr><td>{{x.username}}</td><td>{{x.role}}</td><td>{{x.active}}</td></tr>{% endfor %}</table></div>
    <div class=card><h3>Recent audit activity (latest 300)</h3><table><tr><th>Time UTC</th><th>Actor</th><th>Action</th><th>Document ID</th><th>Details</th></tr>
    {% for x in logs %}<tr><td>{{x.at}}</td><td>{{x.actor_name}}</td><td>{{x.action}}</td><td>{{x.document_id or '-'}}</td><td>{{x.details}}</td></tr>{% endfor %}</table></div>"""
    return page("Admin",body,docs=docs,users=users,logs=logs)

@app.route("/admin/audit-verify")
@login_required
@role_required("admin")
def audit_verify():
    rows=db().execute("SELECT * FROM audit ORDER BY id").fetchall(); prev="GENESIS"
    for r in rows:
        payload=json.dumps({"at":r["at"],"actor_id":r["actor_id"],"actor_name":r["actor_name"],"action":r["action"],"document_id":r["document_id"],"details":json.loads(r["details"])},sort_keys=True,separators=(",",":"))
        expected=hmac.new(AUDIT_KEY,(prev+payload).encode(),hashlib.sha256).hexdigest()
        if r["previous_hash"]!=prev or not hmac.compare_digest(expected,r["entry_hash"]):
            return "AUDIT CHAIN INVALID at entry "+str(r["id"]),500
        prev=r["entry_hash"]
    return "Audit chain verified: "+str(len(rows))+" entries."

@app.route("/admin/users",methods=["GET","POST"])
@login_required
@role_required("admin")
def users_admin():
    if request.method=="POST":
        name=request.form.get("username","").strip()
        password=request.form.get("password","")
        role=request.form.get("role","")
        if len(name)<3 or len(password)<12 or role not in ("admin","owner","viewer"):
            flash("Username must be 3+ chars, password 12+ chars, and role valid.")
        else:
            try:
                db().execute("INSERT INTO users(username,password_hash,role,created_at) VALUES(?,?,?,?)",(name,generate_password_hash(password),role,now()))
                db().commit(); audit(current_user()["id"],current_user()["username"],"USER_CREATED",details={"username":name,"role":role}); flash("User created.")
            except sqlite3.IntegrityError: flash("Username already exists.")
    us=db().execute("SELECT id,username,role,active FROM users ORDER BY username").fetchall()
    return page("Users", """<h1>Manage accounts</h1><div class=card><form method=post><input type=hidden name=_csrf value="{{csrf_token()}}">
    <input name=username placeholder="Username" required><input name=password type=password placeholder="Temporary password (12+ chars)" required>
    <select name=role><option>viewer</option><option>owner</option><option>admin</option></select><button>Create user</button></form></div>
    <div class=card><table><tr><th>Username</th><th>Role</th><th>Active</th></tr>{% for x in us %}<tr><td>{{x.username}}</td><td>{{x.role}}</td><td>{{x.active}}</td></tr>{% endfor %}</table></div>""",us=us)

@app.context_processor
def admin_link():
    u=current_user()
    return {"is_admin": bool(u and u["role"]=="admin")}

@app.after_request
def add_headers(response):
    response.headers["X-Content-Type-Options"]="nosniff"
    response.headers["X-Frame-Options"]="DENY"
    response.headers["Referrer-Policy"]="no-referrer"
    response.headers["Cache-Control"]="no-store"
    response.headers["Content-Security-Policy"]="default-src 'self'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'self'"
    return response

@app.cli.command("init-db")
def init_db_cmd():
    init_db(); print("Database initialised.")

@app.cli.command("seed-demo")
def seed_demo():
    init_db()
    conn=sqlite3.connect(DB_PATH)
    samples=[("admin","AdminDemo!2026Secure","admin"),("owner1","OwnerDemo!2026Secure","owner"),("viewer1","ViewerDemo!2026Secure","viewer"),("viewer2","ViewerTwo!2026Secure","viewer")]
    for name,pw,role in samples:
        try: conn.execute("INSERT INTO users(username,password_hash,role,created_at) VALUES(?,?,?,?)",(name,generate_password_hash(pw),role,now()))
        except sqlite3.IntegrityError: pass
    conn.commit(); conn.close()
    print("Demo users created if absent. Change all passwords before public deployment.")

if __name__=="__main__":
    init_db()
    app.run(debug=os.environ.get("FLASK_DEBUG","0")=="1")
