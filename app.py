import os
import re
import secrets
from datetime import datetime, timedelta
from functools import wraps
from io import StringIO
import csv
from collections import defaultdict

from flask import (
    Flask, request, redirect, url_for, render_template_string,
    flash, send_file, abort, session, Response
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
    SECRET_KEY = secrets.token_hex(32)

WHATSAPP_NUMBER = os.getenv("WHATSAPP_NUMBER", "")  # e.g. 54911XXXXXXXXX
PUBLIC_WHATSAPP_TEXT = os.getenv(
    "WHATSAPP_TEXT",
    "Hola, cargué mal una nota en el sistema NUR. ¿Me ayudan a corregirla?"
)

# SQLite path
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
INSTANCE_DIR = os.path.join(BASE_DIR, "instance")
os.makedirs(INSTANCE_DIR, exist_ok=True)
DB_PATH = os.getenv("NUR_DB_PATH", os.path.join(INSTANCE_DIR, "nur.db"))
DB_URI = os.getenv("DATABASE_URL")

DB_URI = os.getenv("DATABASE_URL")

if DB_URI:
    # Railway a veces entrega postgres:// y SQLAlchemy espera postgresql://
    if DB_URI.startswith("postgres://"):
        DB_URI = DB_URI.replace("postgres://", "postgresql://", 1)
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
app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
    "pool_pre_ping": True,
    if SQLALCHEMY_DATABASE_URI.startswith("sqlite:"):
    engine_opts["connect_args"] = {"check_same_thread": False}

app.config["SQLALCHEMY_ENGINE_OPTIONS"] = engine_opts

# Proxy fix para Railway/Render
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_port=1)

# Cookies seguras en producción
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

# Rate limiting simple (en memoria)
login_attempts = defaultdict(list)

def check_rate_limit(ip: str, max_attempts: int = 10, window_minutes: int = 5) -> bool:
    """Rate limiting simple para prevenir ataques de fuerza bruta"""
    now = datetime.utcnow()
    cutoff = now - timedelta(minutes=window_minutes)
    
    # Limpiar intentos antiguos
    login_attempts[ip] = [t for t in login_attempts[ip] if t > cutoff]
    
    # Verificar límite
    if len(login_attempts[ip]) >= max_attempts:
        return False
    
    # Registrar intento
    login_attempts[ip].append(now)
    return True

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


LEGAJO_MIN = 500000
LEGAJO_MAX = 512000


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
    if val < LEGAJO_MIN or val > LEGAJO_MAX:
        return False, f"Legajo fuera de rango ({LEGAJO_MIN} a {LEGAJO_MAX}). Revisá el número."
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
    role = db.Column(db.String(20), nullable=False, default=OP_ROLE, index=True)

    def set_password(self, pw: str) -> None:
        self.password_hash = generate_password_hash(pw)

    def check_password(self, pw: str) -> bool:
        return check_password_hash(self.password_hash, pw)


class Nota(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nro_nota = db.Column(db.String(50), nullable=False, index=True)
    autoriza = db.Column(db.String(10), nullable=False, index=True)
    puesto = db.Column(db.String(50), nullable=False, index=True)
    estado = db.Column(db.String(15), nullable=False, default="PENDIENTE", index=True)
    
    entrega_nombre = db.Column(db.String(120))
    entrega_legajo = db.Column(db.String(20))
    recibe_nombre = db.Column(db.String(120))
    recibe_legajo = db.Column(db.String(20))
    fecha_hora_recepcion = db.Column(db.DateTime, index=True)
    observaciones = db.Column(db.Text)
    
    creado_por = db.Column(db.String(120))
    creado_en = db.Column(db.DateTime, default=datetime.utcnow)
    completado_por = db.Column(db.String(120))
    completado_en = db.Column(db.DateTime)


class ErrorReporte(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nota_id = db.Column(db.Integer, db.ForeignKey("nota.id"), index=True)
    nro_nota = db.Column(db.String(50))
    puesto = db.Column(db.String(50))
    reportado_por = db.Column(db.String(120))
    detalle = db.Column(db.Text, nullable=False)
    creado_en = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    estado = db.Column(db.String(20), default="ABIERTO", index=True)


@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))


# =========================
# Bootstrap
# =========================
def bootstrap_users() -> None:
    """Crea usuarios por defecto SOLO si la base está vacía."""
    if User.query.count() > 0:
        return

    admin_user = os.getenv("ADMIN_USER", "admin")
    admin_pass = os.getenv("ADMIN_PASS", "AdminSecure2025!")
    op_user = os.getenv("OP_USER", "PSA")
    op_pass = os.getenv("OP_PASS", "OpSecure2025!")

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
# UI Templates (igual que antes, copio completo para que no haya dudas)
# =========================
BASE_HTML = r"""
<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>{{ title }}</title>
<style>
  :root {
    --primary: #2563eb;
    --success: #16a34a;
    --danger: #dc2626;
    --warning: #f59e0b;
    --dark: #1f2937;
    --light: #f3f4f6;
    --highlight: #7c3aed;
  }
  * { margin:0; padding:0; box-sizing:border-box; }
  body { 
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
    min-height: 100vh;
    padding: 20px;
  }
  .container {
    max-width: 1400px;
    margin: 0 auto;
    background: white;
    border-radius: 12px;
    box-shadow: 0 20px 60px rgba(0,0,0,0.3);
    overflow: hidden;
  }
  .header {
    background: linear-gradient(135deg, #1f2937 0%, #111827 100%);
    color: white;
    padding: 20px 30px;
    display: flex;
    justify-content: space-between;
    align-items: center;
    flex-wrap: wrap;
    gap: 15px;
  }
  .header h1 {
    font-size: 24px;
    font-weight: 700;
  }
  .header-actions {
    display: flex;
    gap: 10px;
    align-items: center;
  }
  .btn {
    padding: 10px 20px;
    border: none;
    border-radius: 6px;
    cursor: pointer;
    font-size: 14px;
    font-weight: 600;
    text-decoration: none;
    display: inline-block;
    transition: all 0.3s;
  }
  .btn-primary { background: var(--primary); color: white; }
  .btn-primary:hover { background: #1d4ed8; transform: translateY(-2px); }
  .btn-success { background: var(--success); color: white; }
  .btn-success:hover { background: #15803d; }
  .btn-danger { background: var(--danger); color: white; }
  .btn-danger:hover { background: #b91c1c; }
  .btn-warning { background: var(--warning); color: white; }
  .btn-warning:hover { background: #d97706; }
  .btn-secondary { background: #6b7280; color: white; }
  .btn-secondary:hover { background: #4b5563; }
  
  .content { padding: 30px; }
  
  .alert {
    padding: 15px 20px;
    border-radius: 8px;
    margin-bottom: 20px;
    font-weight: 500;
  }
  .alert-success { background: #d1fae5; color: #065f46; border-left: 4px solid var(--success); }
  .alert-danger { background: #fee2e2; color: #991b1b; border-left: 4px solid var(--danger); }
  .alert-warning { background: #fef3c7; color: #92400e; border-left: 4px solid var(--warning); }
  
  .form-group {
    margin-bottom: 20px;
  }
  .form-group label {
    display: block;
    font-weight: 600;
    margin-bottom: 8px;
    color: var(--dark);
  }
  .form-group input, .form-group select, .form-group textarea {
    width: 100%;
    padding: 12px;
    border: 2px solid #e5e7eb;
    border-radius: 6px;
    font-size: 14px;
    transition: border-color 0.3s;
  }
  .form-group input:focus, .form-group select:focus, .form-group textarea:focus {
    outline: none;
    border-color: var(--primary);
  }
  
  table {
    width: 100%;
    border-collapse: collapse;
    margin-top: 20px;
    background: white;
    box-shadow: 0 1px 3px rgba(0,0,0,0.1);
    border-radius: 8px;
    overflow: hidden;
  }
  thead {
    background: linear-gradient(135deg, #1f2937 0%, #111827 100%);
    color: white;
  }
  th, td {
    padding: 15px;
    text-align: left;
    border-bottom: 1px solid #e5e7eb;
  }
  tbody tr:hover {
    background: #f9fafb;
  }
  
  .badge {
    padding: 6px 12px;
    border-radius: 20px;
    font-size: 12px;
    font-weight: 700;
    display: inline-block;
  }
  .badge-pending { background: #fef3c7; color: #92400e; }
  .badge-completed { background: #d1fae5; color: #065f46; }
  .badge-open { background: #fee2e2; color: #991b1b; }
  .badge-closed { background: #e0e7ff; color: #3730a3; }
  
  .panel {
    background: white;
    border-radius: 8px;
    padding: 25px;
    margin-bottom: 25px;
    box-shadow: 0 2px 8px rgba(0,0,0,0.1);
  }
  
  .panel-highlight {
    background: linear-gradient(135deg, #7c3aed 0%, #5b21b6 100%);
    color: white;
    border: 3px solid #fbbf24;
    box-shadow: 0 8px 20px rgba(124,58,237,0.4);
    animation: pulse 2s infinite;
  }
  
  @keyframes pulse {
    0%, 100% { box-shadow: 0 8px 20px rgba(124,58,237,0.4); }
    50% { box-shadow: 0 12px 30px rgba(124,58,237,0.6); }
  }
  
  .panel-highlight h2 {
    color: white;
    font-size: 22px;
    margin-bottom: 15px;
    text-shadow: 2px 2px 4px rgba(0,0,0,0.3);
  }
  
  .panel-highlight label {
    color: white !important;
  }
  
  .panel h2 {
    color: var(--dark);
    font-size: 20px;
    margin-bottom: 20px;
    border-bottom: 3px solid var(--primary);
    padding-bottom: 10px;
  }
  
  .grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
    gap: 20px;
  }
  
  .login-box {
    max-width: 450px;
    margin: 100px auto;
    background: white;
    padding: 40px;
    border-radius: 12px;
    box-shadow: 0 20px 60px rgba(0,0,0,0.3);
  }
  
  .login-box h1 {
    color: var(--dark);
    margin-bottom: 30px;
    text-align: center;
  }
  
  .small-text {
    font-size: 13px;
    color: #6b7280;
    margin-top: 5px;
  }
</style>
</head>
<body>
{% if current_user.is_authenticated %}
<div class="container">
  <div class="header">
    <h1>{{ APP_NAME }}</h1>
    <div class="header-actions">
      <span style="margin-right:15px;">👤 {{ current_user.username }} ({{ current_user.role }})</span>
      {% if current_user.role == 'admin' %}
        <a href="{{ url_for('admin_home') }}" class="btn btn-primary">Panel Admin</a>
        <a href="{{ url_for('admin_usuarios') }}" class="btn btn-secondary">Usuarios</a>
        <a href="{{ url_for('admin_errores') }}" class="btn btn-warning">Errores</a>
      {% else %}
        <a href="{{ url_for('operador_home') }}" class="btn btn-primary">Seleccionar Puesto</a>
        <a href="{{ url_for('operador_reportar_inicio') }}" class="btn btn-warning">🚨 Reportar ERROR</a>
      {% endif %}
      <a href="{{ url_for('logout') }}" class="btn btn-danger">Salir</a>
    </div>
  </div>
  <div class="content">
    {% with messages = get_flashed_messages(with_categories=true) %}
      {% if messages %}
        {% for category, message in messages %}
          <div class="alert alert-{{ category }}">{{ message }}</div>
        {% endfor %}
      {% endif %}
    {% endwith %}
    {% block content %}{% endblock %}
  </div>
</div>
{% else %}
  {% block login %}{% endblock %}
{% endif %}
</body>
</html>
"""

LOGIN_HTML = BASE_HTML + r"""
{% block login %}
<div class="login-box">
  <h1>🔐 {{ APP_NAME }}</h1>
  <form method="POST">
    <div class="form-group">
      <label>Usuario</label>
      <input type="text" name="username" required autofocus />
    </div>
    <div class="form-group">
      <label>Contraseña</label>
      <input type="password" name="password" required />
    </div>
    <button type="submit" class="btn btn-primary" style="width:100%;">Ingresar</button>
  </form>
  <p class="small-text" style="margin-top:20px; text-align:center;">
    Usá tu usuario y contraseña.
  </p>
</div>
{% endblock %}
"""

ADMIN_HOME_HTML = BASE_HTML + r"""
{% block content %}
<div class="panel panel-highlight">
  <h2>📝 REGISTRAR NOTA</h2>
  <p style="margin-bottom:20px; font-size:15px;">
    Acá prefijás las notas (número, autoriza y puesto). El operador solo completa entrega/recepción.
  </p>
  <p style="margin-bottom:20px; font-size:14px;">
    <strong>Importante:</strong> Creá una fila por cada puesto. Si el mismo N° va a 5 puestos, creás 5 notas (una por puesto).
  </p>
  <form method="POST" action="{{ url_for('admin_crear_nota') }}">
    <div class="grid">
      <div class="form-group">
        <label>N° Nota</label>
        <input type="text" name="nro_nota" required />
      </div>
      <div class="form-group">
        <label>Autoriza</label>
        <select name="autoriza" required>
          <option value="">-- Seleccionar --</option>
          <option value="AVSEC">AVSEC</option>
          <option value="OPER">OPER</option>
        </select>
      </div>
      <div class="form-group">
        <label>Puesto</label>
        <input type="text" name="puesto" required placeholder="Ej: GATE A3, PAMPA, etc." />
      </div>
    </div>
    <button type="submit" class="btn btn-success" style="width:100%; font-size:16px;">✅ Crear Nota</button>
  </form>
</div>

<div class="panel">
  <h2>📋 Notas Registradas</h2>
  <form method="GET" style="margin-bottom:20px;">
    <div class="grid">
      <div class="form-group">
        <label>Filtrar por N° Nota</label>
        <input type="text" name="nro_nota" value="{{ request.args.get('nro_nota','') }}" />
      </div>
      <div class="form-group">
        <label>Filtrar por Autoriza</label>
        <select name="autoriza">
          <option value="">Todos</option>
          <option value="AVSEC" {{ 'selected' if request.args.get('autoriza')=='AVSEC' }}>AVSEC</option>
          <option value="OPER" {{ 'selected' if request.args.get('autoriza')=='OPER' }}>OPER</option>
        </select>
      </div>
      <div class="form-group">
        <label>Filtrar por Puesto</label>
        <input type="text" name="puesto" value="{{ request.args.get('puesto','') }}" />
      </div>
    </div>
    <button type="submit" class="btn btn-primary">🔍 Filtrar</button>
    <a href="{{ url_for('admin_exportar_csv', **request.args) }}" class="btn btn-success">📥 Exportar CSV</a>
    <a href="{{ url_for('admin_home') }}" class="btn btn-secondary">🔄 Limpiar filtros</a>
  </form>
  
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
        <th>Acciones</th>
      </tr>
    </thead>
    <tbody>
      {% for n in notas %}
      <tr>
        <td>{{ n.id }}</td>
        <td><strong>{{ n.nro_nota }}</strong></td>
        <td>{{ n.autoriza }}</td>
        <td>{{ n.puesto }}</td>
        <td>
          {% if n.estado == 'PENDIENTE' %}
            <span class="badge badge-pending">PENDIENTE</span>
          {% else %}
            <span class="badge badge-completed">COMPLETADA</span>
          {% endif %}
        </td>
        <td>{{ n.entrega_nombre or '' }} {{ ('('+n.entrega_legajo+')') if n.entrega_legajo else '' }}</td>
        <td>{{ n.recibe_nombre or '' }} {{ ('('+n.recibe_legajo+')') if n.recibe_legajo else '' }}</td>
        <td>{{ n.fecha_hora_recepcion.strftime('%d/%m %H:%M') if n.fecha_hora_recepcion else '' }}</td>
        <td>
          <form method="POST" action="{{ url_for('admin_borrar_nota', nota_id=n.id) }}" style="display:inline;"
                onsubmit="return confirm('¿Borrar nota #{{ n.id }}?');">
            <button type="submit" class="btn btn-danger" style="padding:6px 12px; font-size:12px;">🗑️ Borrar</button>
          </form>
        </td>
      </tr>
      {% endfor %}
    </tbody>
  </table>
  <p class="small-text" style="margin-top:15px;">Mostrando hasta 250 registros.</p>
</div>
{% endblock %}
"""

ADMIN_USUARIOS_HTML = BASE_HTML + r"""
{% block content %}
<div class="panel">
  <h2>👥 Gestión de Usuarios</h2>
  <p style="margin-bottom:20px;">
    Creá un usuario "operador" para completar notas. El operador no ve ni exporta CSV.
  </p>
  
  <form method="POST" action="{{ url_for('admin_crear_usuario') }}" style="margin-bottom:30px;">
    <div class="grid">
      <div class="form-group">
        <label>Nombre de usuario</label>
        <input type="text" name="username" required />
      </div>
      <div class="form-group">
        <label>Contraseña</label>
        <input type="password" name="password" required />
      </div>
      <div class="form-group">
        <label>Rol</label>
        <select name="role" required>
          <option value="operador">Operador</option>
          <option value="admin">Admin</option>
        </select>
      </div>
    </div>
    <button type="submit" class="btn btn-success">➕ Crear Usuario</button>
  </form>
  
  <table>
    <thead>
      <tr>
        <th>Usuario</th>
        <th>Rol</th>
        <th>Acciones</th>
      </tr>
    </thead>
    <tbody>
      {% for u in usuarios %}
      <tr>
        <td>{{ u.username }}</td>
        <td><span class="badge badge-completed">{{ u.role }}</span></td>
        <td>
          <form method="POST" action="{{ url_for('admin_borrar_usuario', user_id=u.id) }}" style="display:inline;"
                onsubmit="return confirm('¿Borrar usuario {{ u.username }}?');">
            <button type="submit" class="btn btn-danger" style="padding:6px 12px; font-size:12px;">🗑️ Borrar</button>
          </form>
        </td>
      </tr>
      {% endfor %}
    </tbody>
  </table>
</div>
{% endblock %}
"""

ADMIN_ERRORES_HTML = BASE_HTML + r"""
{% block content %}
<div class="panel">
  <h2>🚨 Reportes de Errores</h2>
  
  <table>
    <thead>
      <tr>
        <th>ID</th>
        <th>N° Nota</th>
        <th>Puesto</th>
        <th>Reportado por</th>
        <th>Detalle</th>
        <th>Fecha</th>
        <th>Estado</th>
        <th>Acciones</th>
      </tr>
    </thead>
    <tbody>
      {% for e in errores %}
      <tr>
        <td>{{ e.id }}</td>
        <td>{{ e.nro_nota or '' }}</td>
        <td>{{ e.puesto or '' }}</td>
        <td>{{ e.reportado_por }}</td>
        <td>{{ e.detalle[:100] }}...</td>
        <td>{{ e.creado_en.strftime('%d/%m %H:%M') }}</td>
        <td>
          {% if e.estado == 'ABIERTO' %}
            <span class="badge badge-open">ABIERTO</span>
          {% else %}
            <span class="badge badge-closed">CERRADO</span>
          {% endif %}
        </td>
        <td>
          {% if e.estado == 'ABIERTO' %}
          <form method="POST" action="{{ url_for('admin_cerrar_error', err_id=e.id) }}" style="display:inline;">
            <button type="submit" class="btn btn-success" style="padding:6px 12px; font-size:12px;">✅ Cerrar</button>
          </form>
          {% endif %}
          <form method="POST" action="{{ url_for('admin_borrar_error', err_id=e.id) }}" style="display:inline;"
                onsubmit="return confirm('¿Borrar reporte #{{ e.id }}?');">
            <button type="submit" class="btn btn-danger" style="padding:6px 12px; font-size:12px;">🗑️ Borrar</button>
          </form>
        </td>
      </tr>
      {% endfor %}
    </tbody>
  </table>
  <p class="small-text" style="margin-top:15px;">Mostrando hasta 200 registros.</p>
</div>
{% endblock %}
"""

OPERADOR_HOME_HTML = BASE_HTML + r"""
{% block content %}
<div class="panel">
  <h2>📍 Selección de Puesto</h2>
  <p style="margin-bottom:20px;">
    Elegí un puesto para ver las notas <strong>pendientes</strong> y completarlas.
  </p>
  <p style="margin-bottom:20px; font-size:14px; color:#6b7280;">
    <strong>Tip:</strong> Guardá tu "Selección" (entrega global + recibe por puesto) y después es "Completar y siguiente".
  </p>
  
  <div class="form-group">
    <label>Puesto</label>
    <select id="selectPuesto" class="form-control">
      <option value="">-- Seleccionar puesto --</option>
      {% for p in puestos %}
        <option value="{{ p }}">{{ p }}</option>
      {% endfor %}
    </select>
  </div>
  <button onclick="irPuesto()" class="btn btn-primary">📂 Ver Notas del Puesto</button>
</div>

<script>
function irPuesto() {
  const p = document.getElementById('selectPuesto').value;
  if (!p) { alert('Seleccioná un puesto'); return; }
  window.location.href = "{{ url_for('operador_puesto', puesto='__PUESTO__') }}".replace('__PUESTO__', encodeURIComponent(p));
}
</script>
{% endblock %}
"""

OPERADOR_PUESTO_HTML = BASE_HTML + r"""
{% block content %}
<div class="panel">
  <h2>📋 Puesto: {{ puesto }}</h2>
  <p style="margin-bottom:20px;">
    Seleccioná una nota pendiente y completala. Si vas a completar varias seguidas, guardá la selección y después es "Completar y siguiente".
  </p>
  <p style="margin-bottom:20px; font-size:13px; color:#dc2626;">
    <strong>⚠️ Importante:</strong> Si el legajo tiene puntos o comas (ej: 501.123 o 501,123), va a dar error: usá solo números.
  </p>
</div>

<div class="panel">
  <h2>💾 Datos de Sesión (se borran al salir)</h2>
  <form method="POST" action="{{ url_for('operador_guardar_defaults') }}">
    <input type="hidden" name="puesto" value="{{ puesto }}" />
    <div class="grid">
      <div class="form-group">
        <label>Entrega - Nombre</label>
        <input type="text" name="entrega_nombre" value="{{ defaults.entrega_nombre or '' }}" />
      </div>
      <div class="form-group">
        <label>Entrega - Legajo</label>
        <input type="text" name="entrega_legajo" value="{{ defaults.entrega_legajo or '' }}" placeholder="Ej: 501123" />
      </div>
      <div class="form-group">
        <label>Recibe - Nombre</label>
        <input type="text" name="recibe_nombre" value="{{ defaults.recibe_nombre or '' }}" />
      </div>
      <div class="form-group">
        <label>Recibe - Legajo</label>
        <input type="text" name="recibe_legajo" value="{{ defaults.recibe_legajo or '' }}" placeholder="Ej: 502456" />
      </div>
    </div>
    <button type="submit" class="btn btn-success">💾 Guardar Selección</button>
  </form>
</div>

{% if notas %}
<div class="panel">
  <h2>📝 Notas Pendientes ({{ notas|length }})</h2>
  <table>
    <thead>
      <tr>
        <th>ID</th>
        <th>N° Nota</th>
        <th>Autoriza</th>
        <th>Acciones</th>
      </tr>
    </thead>
    <tbody>
      {% for n in notas %}
      <tr>
        <td>{{ n.id }}</td>
        <td><strong>{{ n.nro_nota }}</strong></td>
        <td>{{ n.autoriza }}</td>
        <td>
          <a href="{{ url_for('operador_completar_nota', nota_id=n.id) }}" class="btn btn-primary" style="padding:6px 12px; font-size:12px;">✏️ Completar</a>
        </td>
      </tr>
      {% endfor %}
    </tbody>
  </table>
</div>
{% else %}
<div class="alert alert-warning">
  ✅ No hay notas pendientes para este puesto.
</div>
{% endif %}

<a href="{{ url_for('operador_home') }}" class="btn btn-secondary">← Volver a selección de puesto</a>
{% endblock %}
"""

OPERADOR_COMPLETAR_HTML = BASE_HTML + r"""
{% block content %}
<div class="panel">
  <h2>✏️ Completar Nota #{{ nota.id }}</h2>
  <p><strong>N° Nota:</strong> {{ nota.nro_nota }} | <strong>Autoriza:</strong> {{ nota.autoriza }} | <strong>Puesto:</strong> {{ nota.puesto }}</p>
</div>

<div class="panel">
  <form method="POST">
    <div class="grid">
      <div class="form-group">
        <label>Entrega - Nombre</label>
        <input type="text" name="entrega_nombre" value="{{ pre.entrega_nombre or '' }}" required />
      </div>
      <div class="form-group">
        <label>Entrega - Legajo</label>
        <input type="text" name="entrega_legajo" value="{{ pre.entrega_legajo or '' }}" required placeholder="Ej: 501123" />
      </div>
      <div class="form-group">
        <label>Recibe - Nombre</label>
        <input type="text" name="recibe_nombre" value="{{ pre.recibe_nombre or '' }}" required />
      </div>
      <div class="form-group">
        <label>Recibe - Legajo</label>
        <input type="text" name="recibe_legajo" value="{{ pre.recibe_legajo or '' }}" required placeholder="Ej: 502456" />
      </div>
      <div class="form-group">
        <label>Fecha y Hora de Recepción</label>
        <input type="datetime-local" name="fecha_hora_recepcion" required />
      </div>
      <div class="form-group">
        <label>Observaciones (opcional)</label>
        <textarea name="observaciones" rows="3"></textarea>
      </div>
    </div>
    <button type="submit" class="btn btn-success">✅ Completar Nota</button>
    <a href="{{ url_for('operador_puesto', puesto=nota.puesto) }}" class="btn btn-secondary">← Cancelar</a>
  </form>
</div>
{% endblock %}
"""

OPERADOR_REPORTAR_HTML = BASE_HTML + r"""
{% block content %}
<div class="panel">
  <h2>🚨 Reportar Error</h2>
  <p style="margin-bottom:20px;">
    Si completaste mal una nota, reportalo acá. Queda registrado en la base como "error" para que el admin lo corrija.
  </p>
  {% if wsp_link %}
  <p style="margin-bottom:20px;">
    También podés contactar por WhatsApp: <a href="{{ wsp_link }}" target="_blank" class="btn btn-success">📱 WhatsApp</a>
  </p>
  {% endif %}
</div>

<div class="panel">
  <form method="POST">
    {% if nota %}
    <div class="alert alert-warning">
      Reportando problema con: <strong>Nota #{{ nota.id }} - {{ nota.nro_nota }} ({{ nota.puesto }})</strong>
    </div>
    <input type="hidden" name="nota_id" value="{{ nota.id }}" />
    {% endif %}
    
    <div class="form-group">
      <label>Detalle del problema</label>
      <textarea name="detalle" rows="5" required placeholder="Describí qué cargaste mal o qué necesitás corregir..."></textarea>
    </div>
    
    <button type="submit" class="btn btn-danger">📤 Enviar Reporte</button>
    {% if nota %}
      <a href="{{ url_for('operador_puesto', puesto=nota.puesto) }}" class="btn btn-secondary">← Cancelar</a>
    {% else %}
      <a href="{{ url_for('operador_home') }}" class="btn btn-secondary">← Cancelar</a>
    {% endif %}
  </form>
</div>
{% endblock %}
"""

ERROR_HTML = r"""
<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="UTF-8"/>
<title>Error</title>
<style>
  body { font-family: sans-serif; text-align:center; padding:50px; }
  h1 { color:#dc2626; }
  a { color:#2563eb; }
</style>
</head>
<body>
<h1>❌ {{ msg }}</h1>
<a href="javascript:history.back()">← Volver</a>
</body>
</html>
"""

# =========================
# Routes
# =========================

@app.route("/")
def index():
    if current_user.is_authenticated:
        if current_user.role == ADMIN_ROLE:
            return redirect(url_for("admin_home"))
        else:
            return redirect(url_for("operador_home"))
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        if current_user.role == ADMIN_ROLE:
            return redirect(url_for("admin_home"))
        else:
            return redirect(url_for("operador_home"))
    
    if request.method == "POST":
        # Rate limiting
        ip = request.remote_addr
        if not check_rate_limit(ip):
            flash("Demasiados intentos. Esperá unos minutos.", "danger")
            return redirect(url_for("login"))
        
        username = sanitize_text(request.form.get("username", ""))
        password = request.form.get("password", "")
        
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            login_user(user)
            flash("Bienvenido!", "success")
            
            # Redirigir según rol
            if user.role == ADMIN_ROLE:
                return redirect(url_for("admin_home"))
            else:
                return redirect(url_for("operador_home"))
        else:
            flash("Usuario o contraseña incorrectos.", "danger")
    
    return render_template_string(LOGIN_HTML, title="Login", APP_NAME=APP_NAME)


@app.route("/logout")
@login_required
def logout():
    # Limpiar datos de sesión
    session.clear()
    logout_user()
    flash("Sesión cerrada correctamente.", "success")
    return redirect(url_for("login"))


# =========================
# Admin Routes
# =========================

@app.route("/admin")
@login_required
@role_required(ADMIN_ROLE)
def admin_home():
    # Filtros
    flt_nro = request.args.get("nro_nota", "").strip()
    flt_aut = request.args.get("autoriza", "").strip()
    flt_puesto = request.args.get("puesto", "").strip()
    
    q = Nota.query
    if flt_nro:
        q = q.filter(Nota.nro_nota.contains(flt_nro))
    if flt_aut:
        q = q.filter(Nota.autoriza == flt_aut)
    if flt_puesto:
        q = q.filter(Nota.puesto.contains(flt_puesto))
    
    notas = q.order_by(Nota.id.desc()).limit(250).all()
    
    return render_template_string(
        ADMIN_HOME_HTML,
        title="Admin - NUR",
        APP_NAME=APP_NAME,
        notas=notas
    )


@app.route("/admin/crear_nota", methods=["POST"])
@login_required
@role_required(ADMIN_ROLE)
def admin_crear_nota():
    try:
        nro_nota = sanitize_text(request.form.get("nro_nota", ""))
        autoriza = sanitize_text(request.form.get("autoriza", ""))
        puesto = sanitize_text(request.form.get("puesto", ""))
        
        if not nro_nota or not autoriza or not puesto:
            flash("Todos los campos son obligatorios.", "danger")
            return redirect(url_for("admin_home"))
        
        if autoriza not in ["AVSEC", "OPER"]:
            flash("Autoriza debe ser AVSEC u OPER.", "danger")
            return redirect(url_for("admin_home"))
        
        nota = Nota(
            nro_nota=nro_nota,
            autoriza=autoriza,
            puesto=puesto,
            estado="PENDIENTE",
            creado_por=current_user.username
        )
        db.session.add(nota)
        db.session.commit()
        
        flash(f"Nota creada: {nro_nota} - {puesto}", "success")
    except Exception as e:
        db.session.rollback()
        flash(f"Error al crear nota: {str(e)}", "danger")
    
    return redirect(url_for("admin_home"))


@app.route("/admin/borrar_nota/<int:nota_id>", methods=["POST"])
@login_required
@role_required(ADMIN_ROLE)
def admin_borrar_nota(nota_id: int):
    try:
        nota = db.session.get(Nota, nota_id)
        if nota:
            db.session.delete(nota)
            db.session.commit()
            flash(f"Nota #{nota_id} borrada.", "success")
        else:
            flash("Nota no encontrada.", "warning")
    except Exception as e:
        db.session.rollback()
        flash(f"Error al borrar: {str(e)}", "danger")
    
    return redirect(url_for("admin_home"))


@app.route("/admin/exportar_csv")
@login_required
@role_required(ADMIN_ROLE)
def admin_exportar_csv():
    try:
        # Filtros seguros
        q = Nota.query
        
        flt_nro = request.args.get("nro_nota", "").strip()
        if flt_nro:
            q = q.filter(Nota.nro_nota.contains(flt_nro))
        
        flt_aut = request.args.get("autoriza", "").strip()
        if flt_aut:
            q = q.filter(Nota.autoriza == flt_aut)
        
        flt_puesto = request.args.get("puesto", "").strip()
        if flt_puesto:
            q = q.filter(Nota.puesto.contains(flt_puesto))
        
        # Límite de seguridad
        notas = q.limit(10000).all()
        
        # Generar CSV
        si = StringIO()
        cw = csv.writer(si)
        cw.writerow([
            "ID", "NroNota", "Autoriza", "Puesto", "Estado",
            "EntregaNombre", "EntregaLegajo",
            "RecibeNombre", "RecibeLegajo",
            "FechaHoraRecepcion", "Observaciones",
            "CreadoPor", "CreadoEn", "CompletadoPor", "CompletadoEn"
        ])
        
        for n in notas:
            cw.writerow([
                n.id,
                n.nro_nota,
                n.autoriza,
                n.puesto,
                n.estado,
                n.entrega_nombre or "",
                n.entrega_legajo or "",
                n.recibe_nombre or "",
                n.recibe_legajo or "",
                n.fecha_hora_recepcion.isoformat() if n.fecha_hora_recepcion else "",
                n.observaciones or "",
                n.creado_por or "",
                n.creado_en.isoformat() if n.creado_en else "",
                n.completado_por or "",
                n.completado_en.isoformat() if n.completado_en else ""
            ])
        
        output = si.getvalue()
        si.close()
        
        return Response(
            output,
            mimetype="text/csv",
            headers={"Content-Disposition": "attachment;filename=notas.csv"}
        )
    except Exception as e:
        flash(f"Error al exportar: {str(e)}", "danger")
        return redirect(url_for("admin_home"))


@app.route("/admin/usuarios")
@login_required
@role_required(ADMIN_ROLE)
def admin_usuarios():
    usuarios = User.query.all()
    return render_template_string(
        ADMIN_USUARIOS_HTML,
        title="Usuarios - Admin",
        APP_NAME=APP_NAME,
        usuarios=usuarios
    )


@app.route("/admin/crear_usuario", methods=["POST"])
@login_required
@role_required(ADMIN_ROLE)
def admin_crear_usuario():
    try:
        username = sanitize_text(request.form.get("username", ""))
        password = request.form.get("password", "")
        role = request.form.get("role", "")
        
        if not username or not password or not role:
            flash("Todos los campos son obligatorios.", "danger")
            return redirect(url_for("admin_usuarios"))
        
        if role not in [ADMIN_ROLE, OP_ROLE]:
            flash("Rol inválido.", "danger")
            return redirect(url_for("admin_usuarios"))
        
        if User.query.filter_by(username=username).first():
            flash(f"Usuario '{username}' ya existe.", "warning")
            return redirect(url_for("admin_usuarios"))
        
        user = User(username=username, role=role)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        
        flash(f"Usuario '{username}' creado.", "success")
    except Exception as e:
        db.session.rollback()
        flash(f"Error al crear usuario: {str(e)}", "danger")
    
    return redirect(url_for("admin_usuarios"))


@app.route("/admin/borrar_usuario/<int:user_id>", methods=["POST"])
@login_required
@role_required(ADMIN_ROLE)
def admin_borrar_usuario(user_id: int):
    try:
        user = db.session.get(User, user_id)
        if user:
            if user.id == current_user.id:
                flash("No podés borrarte a vos mismo.", "danger")
            else:
                db.session.delete(user)
                db.session.commit()
                flash(f"Usuario '{user.username}' borrado.", "success")
        else:
            flash("Usuario no encontrado.", "warning")
    except Exception as e:
        db.session.rollback()
        flash(f"Error al borrar: {str(e)}", "danger")
    
    return redirect(url_for("admin_usuarios"))


@app.route("/admin/errores")
@login_required
@role_required(ADMIN_ROLE)
def admin_errores():
    errores = ErrorReporte.query.order_by(ErrorReporte.creado_en.desc()).limit(200).all()
    return render_template_string(
        ADMIN_ERRORES_HTML,
        title="Errores - Admin",
        APP_NAME=APP_NAME,
        errores=errores
    )


@app.route("/admin/errores/cerrar/<int:err_id>", methods=["POST"])
@login_required
@role_required(ADMIN_ROLE)
def admin_cerrar_error(err_id: int):
    try:
        err = db.session.get(ErrorReporte, err_id)
        if not err:
            flash("Error no encontrado.", "warning")
            return redirect(url_for("admin_errores"))
        
        err.estado = "CERRADO"
        db.session.commit()  # FIX CRÍTICO
        flash("Error marcado como cerrado.", "success")
    except Exception as e:
        db.session.rollback()
        flash(f"Error al cerrar reporte: {str(e)}", "danger")
    
    return redirect(url_for("admin_errores"))


@app.route("/admin/errores/borrar/<int:err_id>", methods=["POST"])
@login_required
@role_required(ADMIN_ROLE)
def admin_borrar_error(err_id: int):
    try:
        err = db.session.get(ErrorReporte, err_id)
        if err:
            db.session.delete(err)
            db.session.commit()
            flash(f"Reporte #{err_id} borrado.", "success")
        else:
            flash("Reporte no encontrado.", "warning")
    except Exception as e:
        db.session.rollback()
        flash(f"Error al borrar: {str(e)}", "danger")
    
    return redirect(url_for("admin_errores"))


# =========================
# Operador Routes
# =========================

@app.route("/operador")
@login_required
@role_required(OP_ROLE)
def operador_home():
    # Lista de puestos únicos con notas pendientes
    puestos = db.session.query(Nota.puesto).filter_by(estado="PENDIENTE").distinct().order_by(Nota.puesto).all()
    puestos = [p[0] for p in puestos]
    
    return render_template_string(
        OPERADOR_HOME_HTML,
        title="Operador - NUR",
        APP_NAME=APP_NAME,
        puestos=puestos
    )


@app.route("/operador/puesto/<puesto>")
@login_required
@role_required(OP_ROLE)
def operador_puesto(puesto: str):
    notas = Nota.query.filter_by(puesto=puesto, estado="PENDIENTE").order_by(Nota.id).all()
    
    # Obtener defaults de sesión
    session_key = f"defaults_{puesto}"
    defaults = session.get(session_key, {})
    
    return render_template_string(
        OPERADOR_PUESTO_HTML,
        title=f"Puesto {puesto} - Operador",
        APP_NAME=APP_NAME,
        puesto=puesto,
        notas=notas,
        defaults=defaults
    )


@app.route("/operador/guardar_defaults", methods=["POST"])
@login_required
@role_required(OP_ROLE)
def operador_guardar_defaults():
    try:
        puesto = request.form.get("puesto", "").strip()
        if not puesto:
            flash("Puesto no especificado.", "danger")
            return redirect(url_for("operador_home"))
        
        # Guardar en sesión (se borra al cerrar sesión)
        session_key = f"defaults_{puesto}"
        session[session_key] = {
            "entrega_nombre": sanitize_text(request.form.get("entrega_nombre", "")),
            "entrega_legajo": normalize_legajo(request.form.get("entrega_legajo", "")),
            "recibe_nombre": sanitize_text(request.form.get("recibe_nombre", "")),
            "recibe_legajo": normalize_legajo(request.form.get("recibe_legajo", ""))
        }
        
        flash("✅ Selección guardada (solo en esta sesión).", "success")
    except Exception as e:
        flash(f"Error al guardar: {str(e)}", "danger")
    
    return redirect(url_for("operador_puesto", puesto=puesto))


@app.route("/operador/completar/<int:nota_id>", methods=["GET", "POST"])
@login_required
@role_required(OP_ROLE)
def operador_completar_nota(nota_id: int):
    nota = db.session.get(Nota, nota_id)
    if not nota:
        return render_template_string(ERROR_HTML, msg="Nota no encontrada."), 404
    
    if nota.estado != "PENDIENTE":
        flash("Esta nota ya fue completada.", "warning")
        return redirect(url_for("operador_puesto", puesto=nota.puesto))
    
    # Cargar defaults de sesión
    session_key = f"defaults_{nota.puesto}"
    pre = session.get(session_key, {})
    
    if request.method == "POST":
        try:
            entrega_nombre = sanitize_text(request.form.get("entrega_nombre", ""))
            entrega_legajo = normalize_legajo(request.form.get("entrega_legajo", ""))
            recibe_nombre = sanitize_text(request.form.get("recibe_nombre", ""))
            recibe_legajo = normalize_legajo(request.form.get("recibe_legajo", ""))
            fecha_str = request.form.get("fecha_hora_recepcion", "")
            observaciones = sanitize_text(request.form.get("observaciones", ""), max_len=500)
            
            # Validaciones
            if not entrega_nombre or not recibe_nombre or not fecha_str:
                flash("Completá todos los campos obligatorios.", "danger")
                return redirect(url_for("operador_completar_nota", nota_id=nota_id))
            
            ok_ent, msg_ent = validate_legajo(entrega_legajo)
            if not ok_ent:
                flash(f"Entrega: {msg_ent}", "danger")
                return redirect(url_for("operador_completar_nota", nota_id=nota_id))
            
            ok_rec, msg_rec = validate_legajo(recibe_legajo)
            if not ok_rec:
                flash(f"Recibe: {msg_rec}", "danger")
                return redirect(url_for("operador_completar_nota", nota_id=nota_id))
            
            try:
                fecha_hora = datetime.fromisoformat(fecha_str)
            except ValueError:
                flash("Formato de fecha inválido.", "danger")
                return redirect(url_for("operador_completar_nota", nota_id=nota_id))
            
            # Actualizar nota
            nota.entrega_nombre = entrega_nombre
            nota.entrega_legajo = entrega_legajo
            nota.recibe_nombre = recibe_nombre
            nota.recibe_legajo = recibe_legajo
            nota.fecha_hora_recepcion = fecha_hora
            nota.observaciones = observaciones
            nota.estado = "COMPLETADA"
            nota.completado_por = current_user.username
            nota.completado_en = datetime.utcnow()
            
            db.session.commit()
            flash(f"✅ Nota #{nota_id} completada.", "success")
            
            return redirect(url_for("operador_puesto", puesto=nota.puesto))
            
        except Exception as e:
            db.session.rollback()
            flash(f"Error al completar: {str(e)}", "danger")
            return redirect(url_for("operador_completar_nota", nota_id=nota_id))
    
    return render_template_string(
        OPERADOR_COMPLETAR_HTML,
        title=f"Completar Nota #{nota_id}",
        APP_NAME=APP_NAME,
        nota=nota,
        pre=pre
    )


@app.route("/operador/reportar_inicio")
@login_required
@role_required(OP_ROLE)
def operador_reportar_inicio():
    """Página para reportar error sin nota específica"""
    wsp_link = None
    if WHATSAPP_NUMBER:
        import urllib.parse
        wsp_link = f"https://wa.me/{WHATSAPP_NUMBER}?text={urllib.parse.quote(PUBLIC_WHATSAPP_TEXT)}"
    
    return render_template_string(
        OPERADOR_REPORTAR_HTML,
        title="Reportar Error",
        APP_NAME=APP_NAME,
        nota=None,
        wsp_link=wsp_link
    )


@app.route("/operador/reportar", methods=["GET", "POST"])
@login_required
@role_required(OP_ROLE)
def operador_reportar():
    """Reportar error con o sin nota específica"""
    nota_id = request.args.get("nota_id") or request.form.get("nota_id")
    puesto = request.args.get("puesto") or request.form.get("puesto")
    
    nota = None
    if nota_id:
        nota = db.session.get(Nota, int(nota_id))
    
    wsp_link = None
    if WHATSAPP_NUMBER:
        import urllib.parse
        wsp_link = f"https://wa.me/{WHATSAPP_NUMBER}?text={urllib.parse.quote(PUBLIC_WHATSAPP_TEXT)}"
    
    if request.method == "POST":
        try:
            detalle = sanitize_text(request.form.get("detalle", ""), max_len=1000)
            if not detalle:
                flash("El detalle es obligatorio.", "danger")
                return redirect(request.url)
            
            err = ErrorReporte(
                nota_id=nota.id if nota else None,
                nro_nota=nota.nro_nota if nota else None,
                puesto=nota.puesto if nota else (puesto or ""),
                reportado_por=current_user.username,
                detalle=detalle
            )
            db.session.add(err)
            db.session.commit()
            
            flash("✅ Reporte enviado. El admin lo revisará.", "success")
            
            if nota:
                return redirect(url_for("operador_puesto", puesto=nota.puesto))
            else:
                return redirect(url_for("operador_home"))
                
        except Exception as e:
            db.session.rollback()
            flash(f"Error al enviar reporte: {str(e)}", "danger")
    
    return render_template_string(
        OPERADOR_REPORTAR_HTML,
        title="Reportar Error",
        APP_NAME=APP_NAME,
        nota=nota,
        wsp_link=wsp_link
    )


# =========================
# Error Handlers
# =========================

@app.errorhandler(403)
def forbidden(e):
    return render_template_string(ERROR_HTML, msg="No tenés permisos para ver esta pantalla."), 403


@app.errorhandler(404)
def not_found(e):
    return render_template_string(ERROR_HTML, msg="La página no existe."), 404


@app.errorhandler(500)
def internal_error(e):
    db.session.rollback()
    return render_template_string(ERROR_HTML, msg="Error interno del servidor."), 500


# =========================
# Run
# =========================
if __name__ == "__main__":
    port = int(os.getenv("PORT", 5000))
    debug = _bool_env("FLASK_DEBUG", False)
    app.run(host="0.0.0.0", port=port, debug=debug)
