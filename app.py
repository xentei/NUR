import os
import re
import secrets
from datetime import datetime
from functools import wraps

from flask import (
    Flask, request, redirect, url_for, render_template_string,
    flash, send_file, abort
)
from flask_login import (
    LoginManager, UserMixin, login_user, login_required,
    logout_user, current_user
)
from flask_sqlalchemy import SQLAlchemy
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.security import generate_password_hash, check_password_hash

# =========================
# Config
# =========================

def _bool_env(name: str, default: bool = False) -> bool:
    v = os.getenv(name)
    if v is None:
        return default
    return v.strip().lower() in {"1", "true", "yes", "y", "on"}

APP_NAME = "NUR - Notas de Autorización"
ADMIN_ROLE = "admin"
OP_ROLE = "operador"

# IMPORTANT: In production, set SECRET_KEY as an environment variable.
SECRET_KEY = os.getenv("SECRET_KEY")
if not SECRET_KEY:
    # Safe enough for local dev; for production set env var.
    SECRET_KEY = secrets.token_hex(32)

WHATSAPP_NUMBER = os.getenv("WHATSAPP_NUMBER", "")  # e.g. 54911XXXXXXXXX
PUBLIC_WHATSAPP_TEXT = os.getenv(
    "WHATSAPP_TEXT",
    "Hola, cargué mal una nota en el sistema NUR. ¿Me ayudan a corregirla?"
)

# SQLite path (works locally and on Railway)
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
INSTANCE_DIR = os.path.join(BASE_DIR, "instance")
os.makedirs(INSTANCE_DIR, exist_ok=True)

DB_PATH = os.getenv("NUR_DB_PATH", os.path.join(INSTANCE_DIR, "nur.db"))
DB_URI = os.getenv("DATABASE_URL")  # if you ever use Postgres, etc.
if DB_URI:
    SQLALCHEMY_DATABASE_URI = DB_URI
else:
    SQLALCHEMY_DATABASE_URI = "sqlite:///" + DB_PATH.replace("\\", "/")

# =========================
# App init
# =========================

app = Flask(__name__)
app.config["SECRET_KEY"] = SECRET_KEY
app.config["SQLALCHEMY_DATABASE_URI"] = SQLALCHEMY_DATABASE_URI
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

# SQLite + gunicorn friendliness
app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
    "pool_pre_ping": True,
    "connect_args": {"check_same_thread": False},
}

# If behind a proxy (Railway/Render), this makes Flask know it's HTTPS.
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_port=1)

# Cookies: lock down on production (when FLASK_DEBUG is not enabled)
if not _bool_env("FLASK_DEBUG", False):
    app.config.update(
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        REMEMBER_COOKIE_HTTPONLY=True,
        REMEMBER_COOKIE_SAMESITE="Lax",
    )

db = SQLAlchemy(app)

login_manager = LoginManager(app)
login_manager.login_view = "login"
login_manager.login_message = "Tenés que iniciar sesión."

# =========================
# Helpers
# =========================

def role_required(*roles):
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            if not current_user.is_authenticated:
                return login_manager.unauthorized()
            if current_user.role not in roles:
                abort(403)
            return fn(*args, **kwargs)
        return wrapper
    return decorator

LEGajo_MIN = 500000
LEGajo_MAX = 512000

def normalize_legajo(raw: str) -> str:
    raw = (raw or "").strip()
    return raw

def validate_legajo(raw: str) -> tuple[bool, str]:
    """
    - Only digits
    - Range: 500000 to 512000
    - No dots/commas/spaces
    """
    raw = normalize_legajo(raw)
    if not raw:
        return False, "El legajo es obligatorio."
    if not raw.isdigit():
        return False, "Legajo inválido: usá solo números (sin puntos ni comas). Ej: 501123"
    val = int(raw)
    if val < LEGajo_MIN or val > LEGajo_MAX:
        return False, f"Legajo fuera de rango ({LEGajo_MIN} a {LEGajo_MAX}). Revisá el número."
    return True, ""

def sanitize_text(s: str, max_len: int = 120) -> str:
    s = (s or "").strip()
    s = re.sub(r"\s+", " ", s)
    return s[:max_len]

# =========================
# Models
# =========================

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), nullable=False, default=OP_ROLE)  # admin / operador

    def set_password(self, pw: str) -> None:
        self.password_hash = generate_password_hash(pw)

    def check_password(self, pw: str) -> bool:
        return check_password_hash(self.password_hash, pw)


class Nota(db.Model):
    id = db.Column(db.Integer, primary_key=True)

    # Prefijado por ADMIN
    nro_nota = db.Column(db.String(50), nullable=False, index=True)
    autoriza = db.Column(db.String(10), nullable=False)  # AVSEC / OPER
    puesto = db.Column(db.String(50), nullable=False, index=True)
    estado = db.Column(db.String(15), nullable=False, default="PENDIENTE")  # PENDIENTE / COMPLETADA

    # Completa OPERADOR (no puede editar lo prefijado)
    entrega_nombre = db.Column(db.String(120))
    entrega_legajo = db.Column(db.String(20))
    recibe_nombre = db.Column(db.String(120))
    recibe_legajo = db.Column(db.String(20))
    fecha_hora_recepcion = db.Column(db.DateTime)
    observaciones = db.Column(db.Text)

    # Auditoría
    creado_por = db.Column(db.String(120))
    creado_en = db.Column(db.DateTime, default=datetime.utcnow)
    completado_por = db.Column(db.String(120))
    completado_en = db.Column(db.DateTime)


class DefaultEntrega(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False, unique=True)
    entrega_nombre = db.Column(db.String(120))
    entrega_legajo = db.Column(db.String(20))
    updated_at = db.Column(db.DateTime, default=datetime.utcnow)


class DefaultRecibe(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    puesto = db.Column(db.String(50), nullable=False)
    recibe_nombre = db.Column(db.String(120))
    recibe_legajo = db.Column(db.String(20))
    updated_at = db.Column(db.DateTime, default=datetime.utcnow)

    __table_args__ = (
        db.UniqueConstraint("user_id", "puesto", name="uq_user_puesto_recibe"),
    )


class ErrorReporte(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nota_id = db.Column(db.Integer, db.ForeignKey("nota.id"))
    nro_nota = db.Column(db.String(50))
    puesto = db.Column(db.String(50))
    reportado_por = db.Column(db.String(120))
    detalle = db.Column(db.Text, nullable=False)
    creado_en = db.Column(db.DateTime, default=datetime.utcnow)
    estado = db.Column(db.String(20), default="ABIERTO")  # ABIERTO / CERRADO


@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

# =========================
# Bootstrap
# =========================

def bootstrap_users() -> None:
    """
    Crea usuarios por defecto SOLO si la base está vacía.
    Para producción, seteá estas variables en Railway:
      - ADMIN_USER, ADMIN_PASS
      - OP_USER, OP_PASS
    """
    if User.query.count() > 0:
        return

    admin_user = os.getenv("ADMIN_USER", "admin")
    admin_pass = os.getenv("ADMIN_PASS", "admin123*")
    op_user = os.getenv("OP_USER", "PSA")
    op_pass = os.getenv("OP_PASS", "123*")

    u1 = User(username=admin_user, role=ADMIN_ROLE)
    u1.set_password(admin_pass)

    u2 = User(username=op_user, role=OP_ROLE)
    u2.set_password(op_pass)

    db.session.add_all([u1, u2])
    db.session.commit()

with app.app_context():
    db.create_all()
    bootstrap_users()

# =========================
# UI templates (single-file)
# =========================

BASE_HTML = r"""
<!doctype html>
<html lang="es">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{{ title }}</title>
  <style>
    :root{
      --bg:#0b1220;
      --panel:#111a2e;
      --card:#0f172a;
      --muted:#94a3b8;
      --text:#e5e7eb;
      --accent:#2563eb;
      --accent2:#10b981;
      --danger:#ef4444;
      --warning:#f59e0b;
      --line:rgba(255,255,255,.10);
      --shadow: 0 12px 30px rgba(0,0,0,.35);
      --radius: 16px;
    }
    *{box-sizing:border-box}
    body{
      margin:0;
      font-family: ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, Helvetica, Arial;
      background: radial-gradient(900px 400px at 10% 10%, rgba(37,99,235,.22), transparent 60%),
                  radial-gradient(900px 400px at 90% 0%, rgba(16,185,129,.16), transparent 55%),
                  var(--bg);
      color:var(--text);
    }
    a{color:inherit}
    .wrap{max-width:980px;margin:0 auto;padding:22px}
    .topbar{
      display:flex;gap:12px;align-items:center;justify-content:space-between;
      padding:14px 16px;border:1px solid var(--line);border-radius:var(--radius);
      background: rgba(17,26,46,.75);
      box-shadow: var(--shadow);
      backdrop-filter: blur(10px);
    }
    .brand{display:flex;flex-direction:column;gap:2px}
    .brand b{font-size:18px;letter-spacing:.2px}
    .brand span{font-size:12px;color:var(--muted)}
    .nav{display:flex;gap:10px;align-items:center;flex-wrap:wrap}
    .pill{
      display:inline-flex;align-items:center;gap:8px;
      padding:8px 12px;border-radius:999px;
      border:1px solid var(--line);background:rgba(15,23,42,.65);
      text-decoration:none;font-size:13px;
    }
    .pill:hover{border-color:rgba(255,255,255,.2)}
    .pill.accent{background:rgba(37,99,235,.18);border-color:rgba(37,99,235,.55)}
    .pill.ok{background:rgba(16,185,129,.14);border-color:rgba(16,185,129,.45)}
    .pill.danger{background:rgba(239,68,68,.12);border-color:rgba(239,68,68,.45)}
    .grid{
      margin-top:18px;
      display:grid;grid-template-columns:1fr;gap:16px;
    }
    @media (min-width: 960px){
      .grid.two{grid-template-columns: 1fr 1fr;}
      .grid.three{grid-template-columns: 1fr 1fr 1fr;}
    }
    .card{
      border:1px solid var(--line);
      background: rgba(15,23,42,.75);
      border-radius: var(--radius);
      box-shadow: var(--shadow);
      padding:16px;
      backdrop-filter: blur(10px);
    }
    h1,h2,h3{margin:0 0 10px 0}
    h1{font-size:22px}
    h2{font-size:18px}
    p{margin:8px 0;color:var(--muted);line-height:1.35}
    .row{display:flex;gap:12px;flex-wrap:wrap}
    .field{display:flex;flex-direction:column;gap:6px;min-width:220px;flex:1}
    label{font-size:12px;color:var(--muted)}
    input,select,textarea{
      padding:10px 10px;border-radius:12px;border:1px solid rgba(255,255,255,.12);
      background: rgba(17,26,46,.8);
      color:var(--text);
      outline:none;
    }
    input:focus,select:focus,textarea:focus{border-color:rgba(37,99,235,.75)}
    textarea{min-height:90px;resize:vertical}
    .btn{
      display:inline-flex;align-items:center;justify-content:center;
      padding:10px 14px;border-radius:12px;border:1px solid rgba(255,255,255,.12);
      background: rgba(255,255,255,.06);
      color:var(--text);cursor:pointer;text-decoration:none;
      font-weight:600;
    }
    .btn:hover{border-color:rgba(255,255,255,.2)}
    .btn.primary{background: rgba(37,99,235,.9);border-color: rgba(37,99,235,1)}
    .btn.primary:hover{filter:brightness(1.04)}
    .btn.success{background: rgba(16,185,129,.85);border-color: rgba(16,185,129,1)}
    .btn.danger{background: rgba(239,68,68,.85);border-color: rgba(239,68,68,1)}
    .btn.small{padding:8px 10px;font-size:12px;border-radius:10px}
    .sep{height:1px;background:var(--line);margin:14px 0}
    .badge{
      display:inline-flex;align-items:center;
      padding:4px 8px;border-radius:999px;font-size:12px;
      border:1px solid var(--line);background:rgba(0,0,0,.12);
      color:var(--muted);
    }
    .badge.ok{color:#d1fae5;border-color:rgba(16,185,129,.5);background:rgba(16,185,129,.10)}
    .badge.warn{color:#fff7ed;border-color:rgba(245,158,11,.55);background:rgba(245,158,11,.10)}
    .badge.danger{color:#fee2e2;border-color:rgba(239,68,68,.55);background:rgba(239,68,68,.10)}
    .flash{padding:10px 12px;border-radius:12px;border:1px solid var(--line);background:rgba(2,6,23,.45);margin:12px 0}
    .flash.ok{border-color:rgba(16,185,129,.55);background:rgba(16,185,129,.10)}
    .flash.err{border-color:rgba(239,68,68,.55);background:rgba(239,68,68,.10)}
    table{width:100%;border-collapse:collapse;overflow:hidden;border-radius:12px}
    th,td{padding:10px;border-bottom:1px solid var(--line);text-align:left;font-size:13px}
    th{color:var(--muted);font-weight:600}
    tr:hover td{background:rgba(255,255,255,.03)}
    .muted{color:var(--muted)}
    .right{margin-left:auto}
    .kpi{display:flex;flex-direction:column;gap:2px}
    .kpi b{font-size:20px}
    .kpi span{font-size:12px;color:var(--muted)}
  </style>
</head>
<body>
  <div class="wrap">
    <div class="topbar">
      <div class="brand">
        <b>{{ app_name }}</b>
        <span>{{ subtitle }}</span>
      </div>
      <div class="nav">
        {% if current_user.is_authenticated %}
          {% if current_user.role == 'admin' %}
            <a class="pill accent" href="{{ url_for('admin') }}">Admin</a>
            <a class="pill" href="{{ url_for('admin_usuarios') }}">Usuarios</a>
            <a class="pill" href="{{ url_for('admin_errores') }}">Errores</a>
          {% endif %}
          <a class="pill ok" href="{{ url_for('operador') }}">Operador</a>
          <a class="pill danger" href="{{ url_for('logout') }}">Salir</a>
        {% else %}
          <a class="pill accent" href="{{ url_for('login') }}">Ingresar</a>
        {% endif %}
      </div>
    </div>

    {% with msgs = get_flashed_messages(with_categories=true) %}
      {% if msgs %}
        {% for cat,msg in msgs %}
          <div class="flash {% if cat=='ok' %}ok{% elif cat=='err' %}err{% endif %}">{{ msg }}</div>
        {% endfor %}
      {% endif %}
    {% endwith %}

    {{ body|safe }}
  </div>
</body>
</html>
"""

def render_page(title: str, body_html: str, subtitle: str = ""):
    return render_template_string(
        BASE_HTML,
        title=title,
        app_name=APP_NAME,
        subtitle=subtitle,
        body=body_html,
        current_user=current_user,
    )

# =========================
# Routes
# =========================

@app.get("/healthz")
def healthz():
    return {"status": "ok"}

@app.get("/")
def index():
    if current_user.is_authenticated:
        return redirect(url_for("operador"))
    return redirect(url_for("login"))

@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("operador"))

    if request.method == "POST":
        username = sanitize_text(request.form.get("username"), 120)
        password = request.form.get("password") or ""
        u = User.query.filter_by(username=username).first()
        if u and u.check_password(password):
            login_user(u, remember=True)
            flash("Sesión iniciada.", "ok")
            nxt = request.args.get("next") or url_for("operador")
            return redirect(nxt)
        flash("Credenciales inválidas.", "err")

    body = r"""
    <div class="grid">
      <div class="card" style="max-width:520px;margin:0 auto;">
        <h1>Ingresar</h1>
        <p>Usá tu usuario y contraseña.</p>
        <form method="post" autocomplete="off">
          <div class="row">
            <div class="field">
              <label>Usuario</label>
              <input name="username" placeholder="Ej: PSA" required>
            </div>
            <div class="field">
              <label>Contraseña</label>
              <input name="password" type="password" required>
            </div>
          </div>
          <div class="sep"></div>
          <button class="btn primary" type="submit">Entrar</button>
          <span class="muted" style="margin-left:10px;font-size:12px;">Si no funciona, revisá que el usuario exista en la base.</span>
        </form>
      </div>
    </div>
    """
    return render_page("Login", body, subtitle="Acceso")


@app.get("/logout")
@login_required
def logout():
    logout_user()
    flash("Sesión cerrada.", "ok")
    return redirect(url_for("login"))

# -------------------------
# Admin
# -------------------------

@app.get("/admin")
@login_required
@role_required(ADMIN_ROLE)
def admin():
    pendientes = Nota.query.filter_by(estado="PENDIENTE").count()
    completadas = Nota.query.filter_by(estado="COMPLETADA").count()
    errores_abiertos = ErrorReporte.query.filter_by(estado="ABIERTO").count()

    body = r"""
    <div class="grid two">
      <div class="card">
        <h1>Panel Admin</h1>
        <p>Acá prefijás las notas (número, autoriza y puesto). El operador solo completa entrega/recepción.</p>
        <div class="row">
          <div class="kpi"><b>{{ pendientes }}</b><span>Pendientes</span></div>
          <div class="kpi"><b>{{ completadas }}</b><span>Completadas</span></div>
          <div class="kpi"><b>{{ errores }}</b><span>Errores abiertos</span></div>
        </div>
        <div class="sep"></div>
        <div class="row">
          <a class="btn" href="{{ url_for('admin_notas') }}">Ver/Buscar notas</a>
          <a class="btn" href="{{ url_for('admin_export_csv') }}">Exportar CSV</a>
        </div>
      </div>

      <div class="card">
        <h2>Crear nota (prefijar)</h2>
        <p>Creá una fila por cada puesto. Si el mismo N° va a 5 puestos, creás 5 notas (una por puesto).</p>

        <form method="post" action="{{ url_for('admin_crear_nota') }}">
          <div class="row">
            <div class="field">
              <label>N° de Nota</label>
              <input name="nro_nota" placeholder="Ej: 9481" required>
            </div>
            <div class="field">
              <label>Autoriza</label>
              <select name="autoriza" required>
                <option value="AVSEC">AVSEC</option>
                <option value="OPER">OPER</option>
              </select>
            </div>
            <div class="field">
              <label>Puesto</label>
              <input name="puesto" placeholder="Ej: BRAVO" required>
            </div>
          </div>
          <div class="row">
            <div class="field">
              <label>Observación (opcional)</label>
              <input name="observaciones" placeholder="Opcional">
            </div>
          </div>
          <div class="sep"></div>
          <button class="btn primary" type="submit">Crear nota</button>
        </form>

        <div class="sep"></div>
        <p class="muted" style="font-size:12px;">
          Sugerencia: si vas a cargar muchas, después te armo un importador CSV/Excel (pero esto ya funciona con lo mínimo).
        </p>
      </div>
    </div>
    """
    return render_template_string(
        BASE_HTML,
        title="Admin",
        app_name=APP_NAME,
        subtitle="Prefijar notas",
        body=render_template_string(body, pendientes=pendientes, completadas=completadas, errores=errores_abiertos),
        current_user=current_user,
    )

@app.post("/admin/crear")
@login_required
@role_required(ADMIN_ROLE)
def admin_crear_nota():
    nro_nota = sanitize_text(request.form.get("nro_nota"), 50)
    autoriza = sanitize_text(request.form.get("autoriza"), 10).upper()
    puesto = sanitize_text(request.form.get("puesto"), 50).upper()
    obs = sanitize_text(request.form.get("observaciones"), 300)

    if autoriza not in {"AVSEC", "OPER"}:
        flash("Autoriza inválido (AVSEC/OPER).", "err")
        return redirect(url_for("admin"))

    if not (nro_nota and puesto):
        flash("Faltan campos obligatorios.", "err")
        return redirect(url_for("admin"))

    n = Nota(
        nro_nota=nro_nota,
        autoriza=autoriza,
        puesto=puesto,
        estado="PENDIENTE",
        observaciones=obs or None,
        creado_por=current_user.username,
    )
    db.session.add(n)
    db.session.commit()
    flash(f"Nota creada: {nro_nota} → {puesto}.", "ok")
    return redirect(url_for("admin"))

@app.get("/admin/notas")
@login_required
@role_required(ADMIN_ROLE)
def admin_notas():
    q = sanitize_text(request.args.get("q", ""), 120)
    estado = sanitize_text(request.args.get("estado", ""), 20).upper()

    query = Nota.query
    if q:
        query = query.filter(
            (Nota.nro_nota.contains(q)) |
            (Nota.puesto.contains(q)) |
            (Nota.autoriza.contains(q))
        )
    if estado in {"PENDIENTE", "COMPLETADA"}:
        query = query.filter_by(estado=estado)

    notas = query.order_by(Nota.creado_en.desc()).limit(250).all()

    body = r"""
    <div class="card">
      <h1>Notas</h1>
      <form method="get" class="row" style="align-items:flex-end">
        <div class="field" style="min-width:260px">
          <label>Buscar (N° / Puesto / Autoriza)</label>
          <input name="q" value="{{ q }}" placeholder="Ej: 9481 o BRAVO">
        </div>
        <div class="field" style="min-width:200px">
          <label>Estado</label>
          <select name="estado">
            <option value="">Todos</option>
            <option value="PENDIENTE" {% if estado=='PENDIENTE' %}selected{% endif %}>PENDIENTE</option>
            <option value="COMPLETADA" {% if estado=='COMPLETADA' %}selected{% endif %}>COMPLETADA</option>
          </select>
        </div>
        <button class="btn primary" type="submit">Filtrar</button>
        <a class="btn" href="{{ url_for('admin') }}">Volver</a>
      </form>

      <div class="sep"></div>
      <table>
        <thead>
          <tr>
            <th>ID</th>
            <th>N° Nota</th>
            <th>Autoriza</th>
            <th>Puesto</th>
            <th>Estado</th>
            <th>Entrega</th>
            <th>Recibe</th>
            <th>Recepción</th>
          </tr>
        </thead>
        <tbody>
          {% for n in notas %}
          <tr>
            <td>{{ n.id }}</td>
            <td>{{ n.nro_nota }}</td>
            <td>{{ n.autoriza }}</td>
            <td>{{ n.puesto }}</td>
            <td>
              {% if n.estado == 'PENDIENTE' %}
                <span class="badge warn">PENDIENTE</span>
              {% else %}
                <span class="badge ok">COMPLETADA</span>
              {% endif %}
            </td>
            <td class="muted">{{ (n.entrega_nombre or '') }} {{ ('('+n.entrega_legajo+')') if n.entrega_legajo else '' }}</td>
            <td class="muted">{{ (n.recibe_nombre or '') }} {{ ('('+n.recibe_legajo+')') if n.recibe_legajo else '' }}</td>
            <td class="muted">{{ n.fecha_hora_recepcion.strftime('%d/%m %H:%M') if n.fecha_hora_recepcion else '' }}</td>
          </tr>
          {% endfor %}
        </tbody>
      </table>
      <p class="muted" style="font-size:12px;margin-top:10px;">Mostrando hasta 250 registros.</p>
    </div>
    """
    return render_template_string(
        BASE_HTML,
        title="Admin - Notas",
        app_name=APP_NAME,
        subtitle="Búsqueda",
        body=render_template_string(body, notas=notas, q=q, estado=estado),
        current_user=current_user,
    )

@app.get("/admin/export.csv")
@login_required
@role_required(ADMIN_ROLE)
def admin_export_csv():
    import csv
    from io import StringIO, BytesIO

    output = StringIO()
    writer = csv.writer(output)
    writer.writerow([
        "id", "nro_nota", "autoriza", "puesto", "estado",
        "entrega_nombre", "entrega_legajo",
        "recibe_nombre", "recibe_legajo",
        "fecha_hora_recepcion", "observaciones",
        "creado_por", "creado_en",
        "completado_por", "completado_en"
    ])

    for n in Nota.query.order_by(Nota.id.asc()).all():
        writer.writerow([
            n.id, n.nro_nota, n.autoriza, n.puesto, n.estado,
            n.entrega_nombre or "", n.entrega_legajo or "",
            n.recibe_nombre or "", n.recibe_legajo or "",
            n.fecha_hora_recepcion.isoformat() if n.fecha_hora_recepcion else "",
            (n.observaciones or "").replace("\n", " ").strip(),
            n.creado_por or "", n.creado_en.isoformat() if n.creado_en else "",
            n.completado_por or "", n.completado_en.isoformat() if n.completado_en else "",
        ])

    bio = BytesIO(output.getvalue().encode("utf-8"))
    bio.seek(0)
    return send_file(
        bio,
        mimetype="text/csv",
        as_attachment=True,
        download_name="nur_export.csv",
    )

@app.route("/admin/usuarios", methods=["GET", "POST"])
@login_required
@role_required(ADMIN_ROLE)
def admin_usuarios():
    if request.method == "POST":
        username = sanitize_text(request.form.get("username"), 120)
        password = request.form.get("password") or ""
        role = sanitize_text(request.form.get("role"), 20)

        if role not in {ADMIN_ROLE, OP_ROLE}:
            flash("Rol inválido.", "err")
            return redirect(url_for("admin_usuarios"))

        if not username or not password:
            flash("Usuario y contraseña son obligatorios.", "err")
            return redirect(url_for("admin_usuarios"))

        if User.query.filter_by(username=username).first():
            flash("Ese usuario ya existe.", "err")
            return redirect(url_for("admin_usuarios"))

        u = User(username=username, role=role)
        u.set_password(password)
        db.session.add(u)
        db.session.commit()
        flash("Usuario creado.", "ok")
        return redirect(url_for("admin_usuarios"))

    users = User.query.order_by(User.username.asc()).all()

    body = r"""
    <div class="grid two">
      <div class="card">
        <h1>Usuarios</h1>
        <p>Creá un usuario “operador” para completar notas. El operador no ve ni exporta CSV.</p>
        <table>
          <thead><tr><th>Usuario</th><th>Rol</th></tr></thead>
          <tbody>
            {% for u in users %}
            <tr><td>{{ u.username }}</td><td class="muted">{{ u.role }}</td></tr>
            {% endfor %}
          </tbody>
        </table>
      </div>

      <div class="card">
        <h2>Crear usuario</h2>
        <form method="post">
          <div class="row">
            <div class="field">
              <label>Usuario</label>
              <input name="username" required>
            </div>
            <div class="field">
              <label>Contraseña</label>
              <input name="password" type="password" required>
            </div>
            <div class="field">
              <label>Rol</label>
              <select name="role">
                <option value="operador">operador</option>
                <option value="admin">admin</option>
              </select>
            </div>
          </div>
          <div class="sep"></div>
          <button class="btn primary" type="submit">Crear</button>
          <a class="btn" href="{{ url_for('admin') }}">Volver</a>
        </form>
      </div>
    </div>
    """
    return render_template_string(
        BASE_HTML,
        title="Admin - Usuarios",
        app_name=APP_NAME,
        subtitle="Roles",
        body=render_template_string(body, users=users),
        current_user=current_user,
    )

@app.get("/admin/errores")
@login_required
@role_required(ADMIN_ROLE)
def admin_errores():
    estado = sanitize_text(request.args.get("estado", "ABIERTO"), 20).upper()
    q = sanitize_text(request.args.get("q", ""), 120)

    query = ErrorReporte.query
    if estado in {"ABIERTO", "CERRADO"}:
        query = query.filter_by(estado=estado)
    if q:
        query = query.filter(
            (ErrorReporte.nro_nota.contains(q)) |
            (ErrorReporte.puesto.contains(q)) |
            (ErrorReporte.detalle.contains(q))
        )

    errores = query.order_by(ErrorReporte.creado_en.desc()).limit(200).all()

    body = r"""
    <div class="card">
      <h1>Errores reportados</h1>
      <form method="get" class="row" style="align-items:flex-end">
        <div class="field" style="min-width:220px">
          <label>Estado</label>
          <select name="estado">
            <option value="ABIERTO" {% if estado=='ABIERTO' %}selected{% endif %}>ABIERTO</option>
            <option value="CERRADO" {% if estado=='CERRADO' %}selected{% endif %}>CERRADO</option>
          </select>
        </div>
        <div class="field" style="min-width:260px">
          <label>Buscar</label>
          <input name="q" value="{{ q }}" placeholder="Ej: 9481 o BRAVO">
        </div>
        <button class="btn primary" type="submit">Filtrar</button>
        <a class="btn" href="{{ url_for('admin') }}">Volver</a>
      </form>

      <div class="sep"></div>
      <table>
        <thead><tr><th>ID</th><th>N° Nota</th><th>Puesto</th><th>Reportado por</th><th>Detalle</th><th>Fecha</th><th>Estado</th></tr></thead>
        <tbody>
          {% for e in errores %}
          <tr>
            <td>{{ e.id }}</td>
            <td>{{ e.nro_nota or '' }}</td>
            <td>{{ e.puesto or '' }}</td>
            <td class="muted">{{ e.reportado_por }}</td>
            <td>{{ e.detalle }}</td>
            <td class="muted">{{ e.creado_en.strftime('%d/%m %H:%M') }}</td>
            <td>
              {% if e.estado == 'ABIERTO' %}
                <span class="badge warn">ABIERTO</span>
              {% else %}
                <span class="badge ok">CERRADO</span>
              {% endif %}
            </td>
          </tr>
          {% endfor %}
        </tbody>
      </table>
      <p class="muted" style="font-size:12px;margin-top:10px;">Mostrando hasta 200 registros.</p>
    </div>
    """
    return render_template_string(
        BASE_HTML,
        title="Admin - Errores",
        app_name=APP_NAME,
        subtitle="Correcciones",
        body=render_template_string(body, errores=errores, estado=estado, q=q),
        current_user=current_user,
    )

# -------------------------
# Operador
# -------------------------

@app.get("/operador")
@login_required
def operador():
    # cualquier usuario autenticado puede entrar, pero la UI cambia por rol
    puestos = (
        db.session.query(Nota.puesto)
        .filter(Nota.estado == "PENDIENTE")
        .distinct()
        .order_by(Nota.puesto.asc())
        .all()
    )
    puestos = [p[0] for p in puestos]

    body = r"""
    <div class="grid two">
      <div class="card">
        <h1>Modo Operador</h1>
        <p>Elegí un puesto para ver las notas <b>pendientes</b> y completarlas.</p>

        <form method="get" action="{{ url_for('operador_puesto') }}">
          <div class="row">
            <div class="field" style="min-width:260px">
              <label>Puesto</label>
              <select name="puesto" required>
                <option value="" selected disabled>Elegir...</option>
                {% for p in puestos %}
                  <option value="{{ p }}">{{ p }}</option>
                {% endfor %}
              </select>
            </div>
            <div class="field" style="min-width:220px">
              <label>&nbsp;</label>
              <button class="btn primary" type="submit">Abrir</button>
            </div>
          </div>
        </form>

        <div class="sep"></div>
        <p class="muted" style="font-size:12px;">
          Tip: guardá tu “Selección” (entrega global + recibe por puesto) y después es “Completar y siguiente”.
        </p>
      </div>

      <div class="card">
        <h2>Atajo para corrección</h2>
        <p>Si completaste algo mal, reportalo desde el puesto con el botón de “Completé mal una planilla”.</p>
        {% if current_user.role == 'admin' %}
          <div class="sep"></div>
          <p class="muted" style="font-size:12px;">Como admin también podés ver y gestionar errores desde el panel.</p>
        {% endif %}
      </div>
    </div>
    """
    return render_template_string(
        BASE_HTML,
        title="Operador",
        app_name=APP_NAME,
        subtitle=f"Usuario: {current_user.username} ({current_user.role})",
        body=render_template_string(body, puestos=puestos),
        current_user=current_user,
    )

@app.get("/operador/puesto")
@login_required
def operador_puesto():
    puesto = sanitize_text(request.args.get("puesto"), 50).upper()
    if not puesto:
        return redirect(url_for("operador"))

    pendientes = Nota.query.filter_by(puesto=puesto, estado="PENDIENTE").order_by(Nota.id.asc()).all()
    if not pendientes:
        flash(f"No hay notas pendientes para {puesto}.", "err")
        return redirect(url_for("operador"))

    # Defaults: entrega global + recibe por puesto
    d_ent = DefaultEntrega.query.filter_by(user_id=current_user.id).first()
    d_rec = DefaultRecibe.query.filter_by(user_id=current_user.id, puesto=puesto).first()

    body = r"""
    <div class="card">
      <div class="row" style="align-items:center">
        <h1 style="margin:0">Puesto: {{ puesto }}</h1>
        <span class="badge warn">{{ pendientes|length }} pendientes</span>
        <a class="btn right" href="{{ url_for('operador') }}">Cambiar puesto</a>
      </div>
      <p>Seleccioná una nota pendiente y completala. Si vas a completar varias seguidas, guardá la selección y después es “Completar y siguiente”.</p>

      <div class="sep"></div>

      <div class="row">
        <div class="field" style="min-width:260px">
          <label>Nota pendiente</label>
          <select id="notaSelect" onchange="location.href=this.value">
            {% for n in pendientes %}
              <option value="{{ url_for('operador_completar', nota_id=n.id) }}"
                {% if n.id == selected_id %}selected{% endif %}
              >ID {{ n.id }} • Nota {{ n.nro_nota }} • {{ n.autoriza }}</option>
            {% endfor %}
          </select>
        </div>
        <div class="field" style="min-width:220px">
          <label>&nbsp;</label>
          <a class="btn" href="{{ url_for('operador_completar', nota_id=selected_id) }}">Abrir</a>
        </div>
      </div>

      <div class="sep"></div>

      <div class="row">
        <a class="btn danger" href="{{ url_for('operador_reportar_error', puesto=puesto, nota_id=selected_id) }}">
          Completé mal una planilla, tocar acá
        </a>
      </div>

      <p class="muted" style="font-size:12px;margin-top:10px;">
        Si el legajo tiene puntos o comas (ej: 501.123 o 501,123), va a dar error: usá solo números.
      </p>
    </div>
    """
    # selected_id default: first pending
    selected_id = int(request.args.get("selected_id") or pendientes[0].id)
    return render_template_string(
        BASE_HTML,
        title="Operador - Puesto",
        app_name=APP_NAME,
        subtitle="Completar notas",
        body=render_template_string(
            body,
            puesto=puesto,
            pendientes=pendientes,
            selected_id=selected_id,
        ),
        current_user=current_user,
    )

@app.route("/operador/completar/<int:nota_id>", methods=["GET", "POST"])
@login_required
def operador_completar(nota_id: int):
    nota = db.session.get(Nota, nota_id)
    if not nota:
        abort(404)
    if nota.estado != "PENDIENTE":
        flash("Esa nota ya fue completada.", "err")
        return redirect(url_for("operador"))

    puesto = nota.puesto

    # Defaults: entrega global + recibe por puesto
    d_ent = DefaultEntrega.query.filter_by(user_id=current_user.id).first()
    d_rec = DefaultRecibe.query.filter_by(user_id=current_user.id, puesto=puesto).first()

    # Initial form values (GET) or posted values (POST)
    if request.method == "POST":
        entrega_nombre = sanitize_text(request.form.get("entrega_nombre"), 120)
        entrega_legajo = normalize_legajo(request.form.get("entrega_legajo"))
        recibe_nombre = sanitize_text(request.form.get("recibe_nombre"), 120)
        recibe_legajo = normalize_legajo(request.form.get("recibe_legajo"))
        observaciones = sanitize_text(request.form.get("observaciones"), 800)

        # Validations
        ok1, msg1 = validate_legajo(entrega_legajo)
        ok2, msg2 = validate_legajo(recibe_legajo)
        if not entrega_nombre or not recibe_nombre:
            flash("Nombre y apellido (entrega/recibe) son obligatorios.", "err")
            return redirect(url_for("operador_completar", nota_id=nota_id))

        if not ok1:
            flash("Entrega: " + msg1, "err")
            return redirect(url_for("operador_completar", nota_id=nota_id))
        if not ok2:
            flash("Recibe: " + msg2, "err")
            return redirect(url_for("operador_completar", nota_id=nota_id))

        action = request.form.get("action", "complete")

        # Save defaults if requested
        if action == "save_defaults":
            # Save entrega globally
            if not d_ent:
                d_ent = DefaultEntrega(user_id=current_user.id)
                db.session.add(d_ent)
            d_ent.entrega_nombre = entrega_nombre
            d_ent.entrega_legajo = entrega_legajo
            d_ent.updated_at = datetime.utcnow()

            # Save recibe per puesto
            if not d_rec:
                d_rec = DefaultRecibe(user_id=current_user.id, puesto=puesto)
                db.session.add(d_rec)
            d_rec.recibe_nombre = recibe_nombre
            d_rec.recibe_legajo = recibe_legajo
            d_rec.updated_at = datetime.utcnow()

            db.session.commit()
            flash("Selección guardada (Entrega global + Recibe por puesto).", "ok")
            return redirect(url_for("operador_completar", nota_id=nota_id))

        # Complete note
        nota.entrega_nombre = entrega_nombre
        nota.entrega_legajo = entrega_legajo
        nota.recibe_nombre = recibe_nombre
        nota.recibe_legajo = recibe_legajo
        nota.fecha_hora_recepcion = datetime.utcnow()
        nota.observaciones = observaciones or None
        nota.estado = "COMPLETADA"
        nota.completado_por = current_user.username
        nota.completado_en = datetime.utcnow()
        db.session.commit()
        flash(f"Nota {nota.nro_nota} ({puesto}) completada.", "ok")

        # Go to next pending in same puesto (fast workflow)
        next_nota = (
            Nota.query.filter_by(puesto=puesto, estado="PENDIENTE")
            .order_by(Nota.id.asc())
            .first()
        )
        if next_nota:
            return redirect(url_for("operador_completar", nota_id=next_nota.id))
        return redirect(url_for("operador"))

    # GET defaults
    entrega_nombre = (d_ent.entrega_nombre if d_ent else "") or ""
    entrega_legajo = (d_ent.entrega_legajo if d_ent else "") or ""
    recibe_nombre = (d_rec.recibe_nombre if d_rec else "") or ""
    recibe_legajo = (d_rec.recibe_legajo if d_rec else "") or ""

    # In case note already has partially filled values (rare)
    entrega_nombre = nota.entrega_nombre or entrega_nombre
    entrega_legajo = nota.entrega_legajo or entrega_legajo
    recibe_nombre = nota.recibe_nombre or recibe_nombre
    recibe_legajo = nota.recibe_legajo or recibe_legajo

    pendientes = Nota.query.filter_by(puesto=puesto, estado="PENDIENTE").order_by(Nota.id.asc()).all()

    body = r"""
    <div class="card">
      <div class="row" style="align-items:center">
        <h1 style="margin:0">Completar nota</h1>
        <span class="badge warn">PENDIENTE</span>
        <span class="right muted" style="font-size:13px;">Puesto: <b style="color:var(--text)">{{ nota.puesto }}</b></span>
      </div>

      <div class="sep"></div>

      <div class="row">
        <div class="kpi"><b>{{ nota.nro_nota }}</b><span>N° Nota</span></div>
        <div class="kpi"><b>{{ nota.autoriza }}</b><span>Autoriza</span></div>
        <div class="kpi"><b>{{ pendientes|length }}</b><span>Pendientes en {{ nota.puesto }}</span></div>
      </div>

      <div class="sep"></div>

      <div class="row">
        <div class="field" style="min-width:260px">
          <label>Ir a otra nota pendiente (mismo puesto)</label>
          <select onchange="location.href=this.value">
            {% for n in pendientes %}
              <option value="{{ url_for('operador_completar', nota_id=n.id) }}" {% if n.id == nota.id %}selected{% endif %}>
                ID {{ n.id }} • Nota {{ n.nro_nota }} • {{ n.autoriza }}
              </option>
            {% endfor %}
          </select>
        </div>
        <div class="field" style="min-width:220px">
          <label>&nbsp;</label>
          <a class="btn" href="{{ url_for('operador') }}">Cambiar puesto</a>
        </div>
      </div>

      <div class="sep"></div>

      <form method="post" autocomplete="off">
        <h2>Datos de entrega</h2>
        <div class="row">
          <div class="field">
            <label>Entrega - Apellido y Nombre</label>
            <input name="entrega_nombre" value="{{ entrega_nombre }}" placeholder="Ej: Pérez Juan" required>
          </div>
          <div class="field">
            <label>Entrega - Legajo ({{ min_leg }} a {{ max_leg }})</label>
            <input name="entrega_legajo" inputmode="numeric" value="{{ entrega_legajo }}" placeholder="Solo números" required>
          </div>
        </div>

        <div class="sep"></div>

        <h2>Datos de recepción (en {{ nota.puesto }})</h2>
        <div class="row">
          <div class="field">
            <label>Recibe - Apellido y Nombre</label>
            <input name="recibe_nombre" value="{{ recibe_nombre }}" placeholder="Ej: Gómez Ana" required>
          </div>
          <div class="field">
            <label>Recibe - Legajo ({{ min_leg }} a {{ max_leg }})</label>
            <input name="recibe_legajo" inputmode="numeric" value="{{ recibe_legajo }}" placeholder="Solo números" required>
          </div>
        </div>

        <div class="sep"></div>

        <div class="row">
          <div class="field">
            <label>Observaciones (opcional)</label>
            <textarea name="observaciones" placeholder="Opcional..."></textarea>
          </div>
        </div>

        <div class="sep"></div>

        <div class="row">
          <button class="btn" type="submit" name="action" value="save_defaults">
            Guardar selección (entrega global + recibe para este puesto)
          </button>

          <button class="btn success" type="submit" name="action" value="complete">
            Completar y siguiente
          </button>

          <a class="btn danger" href="{{ url_for('operador_reportar_error', puesto=nota.puesto, nota_id=nota.id) }}">
            Completé mal una planilla, tocar acá
          </a>
        </div>

        <p class="muted" style="font-size:12px;margin-top:10px;">
          Importante: en legajo usá solo números (sin puntos ni comas). Ej: 501123.
        </p>
      </form>
    </div>
    """
    return render_template_string(
        BASE_HTML,
        title="Completar nota",
        app_name=APP_NAME,
        subtitle=f"Operador: {current_user.username}",
        body=render_template_string(
            body,
            nota=nota,
            pendientes=pendientes,
            entrega_nombre=entrega_nombre,
            entrega_legajo=entrega_legajo,
            recibe_nombre=recibe_nombre,
            recibe_legajo=recibe_legajo,
            min_leg=LEGajo_MIN,
            max_leg=LEGajo_MAX,
        ),
        current_user=current_user,
    )

@app.route("/operador/reportar", methods=["GET", "POST"])
@login_required
def operador_reportar_error():
    puesto = sanitize_text(request.args.get("puesto"), 50).upper()
    nota_id = request.args.get("nota_id")

    nota = None
    if nota_id and str(nota_id).isdigit():
        nota = db.session.get(Nota, int(nota_id))

    if request.method == "POST":
        nro_nota = sanitize_text(request.form.get("nro_nota"), 50)
        puesto_f = sanitize_text(request.form.get("puesto"), 50).upper()
        detalle = sanitize_text(request.form.get("detalle"), 1200)
        nid = request.form.get("nota_id")
        nota_id_val = int(nid) if nid and nid.isdigit() else None

        if not detalle:
            flash("Contame qué salió mal (detalle).", "err")
            return redirect(url_for("operador_reportar_error", puesto=puesto_f or puesto, nota_id=nota_id_val or ""))

        e = ErrorReporte(
            nota_id=nota_id_val,
            nro_nota=nro_nota or (nota.nro_nota if nota else None),
            puesto=puesto_f or (nota.puesto if nota else puesto),
            reportado_por=current_user.username,
            detalle=detalle,
            estado="ABIERTO",
        )
        db.session.add(e)
        db.session.commit()
        flash("Error reportado. Gracias.", "ok")
        return redirect(url_for("operador"))

    wsp_link = ""
    if WHATSAPP_NUMBER:
        import urllib.parse
        msg = urllib.parse.quote(PUBLIC_WHATSAPP_TEXT)
        wsp_link = f"https://wa.me/{WHATSAPP_NUMBER}?text={msg}"

    body = r"""
    <div class="card" style="max-width:720px;margin:0 auto;">
      <h1>Reportar corrección</h1>
      <p>Si completaste mal una nota, reportalo acá. Queda registrado en la base como “error” para que el admin lo corrija.</p>

      {% if wsp_link %}
        <div class="flash ok">
          También podés avisar por WhatsApp:
          <a class="pill ok" href="{{ wsp_link }}" target="_blank" rel="noopener">Abrir WhatsApp</a>
        </div>
      {% endif %}

      <form method="post" autocomplete="off">
        <input type="hidden" name="nota_id" value="{{ nota.id if nota else '' }}">
        <div class="row">
          <div class="field">
            <label>N° de Nota</label>
            <input name="nro_nota" value="{{ nota.nro_nota if nota else '' }}" placeholder="Ej: 9481">
          </div>
          <div class="field">
            <label>Puesto</label>
            <input name="puesto" value="{{ nota.puesto if nota else puesto }}" placeholder="Ej: BRAVO">
          </div>
        </div>
        <div class="row">
          <div class="field">
            <label>¿Qué pasó? (detalle)</label>
            <textarea name="detalle" placeholder="Ej: Cargué mal el legajo / seleccioné nota equivocada / etc." required></textarea>
          </div>
        </div>
        <div class="sep"></div>
        <button class="btn primary" type="submit">Enviar reporte</button>
        <a class="btn" href="{{ url_for('operador') }}">Volver</a>
      </form>
    </div>
    """
    return render_template_string(
        BASE_HTML,
        title="Reportar error",
        app_name=APP_NAME,
        subtitle="Correcciones",
        body=render_template_string(body, puesto=puesto, nota=nota, wsp_link=wsp_link),
        current_user=current_user,
    )

# -------------------------
# Errors
# -------------------------

@app.errorhandler(403)
def err_403(_e):
    body = r"""
    <div class="card" style="max-width:650px;margin:0 auto;">
      <h1>Acceso denegado</h1>
      <p>No tenés permisos para ver esta pantalla.</p>
      <div class="sep"></div>
      <a class="btn" href="{{ url_for('operador') }}">Volver</a>
    </div>
    """
    return render_page("403", body, subtitle="Permisos"), 403

@app.errorhandler(404)
def err_404(_e):
    body = r"""
    <div class="card" style="max-width:650px;margin:0 auto;">
      <h1>No encontrado</h1>
      <p>La página no existe.</p>
      <div class="sep"></div>
      <a class="btn" href="{{ url_for('operador') }}">Volver</a>
    </div>
    """
    return render_page("404", body, subtitle=""), 404

# =========================
# Local run
# =========================

if __name__ == "__main__":
    # Para local: set FLASK_DEBUG=1 si querés autoreload.
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "5000")), debug=_bool_env("FLASK_DEBUG", True))
