import argparse
import os
import re
import shutil
import sqlite3
import secrets
from datetime import datetime, timedelta
from functools import wraps
from io import StringIO
import csv
from collections import defaultdict

from flask import (
    Flask, request, redirect, url_for, render_template,
    flash, send_file, abort, session, Response
)
from flask_login import (
    LoginManager, UserMixin, login_user, login_required,
    logout_user, current_user
)
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import event
from sqlalchemy.engine import Engine
from flask_wtf.csrf import CSRFProtect, generate_csrf
from markupsafe import Markup
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.security import generate_password_hash, check_password_hash

# =========================
# Config
# =========================
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
RAILWAY_VOLUME_PATH = os.getenv("RAILWAY_VOLUME_MOUNT_PATH", "/data")
INSTANCE_DIR = os.path.join(BASE_DIR, "instance")


def _int_env(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, default))
    except Exception:
        return default


def _bool_env(name: str, default: bool = False) -> bool:
    v = os.getenv(name)
    if v is None:
        return default
    return v.strip().lower() in {"1", "true", "yes", "y", "on"}


def _load_secret_key() -> str:
    """Obtiene SECRET_KEY sin fallar, generando y guardando una copia si es posible."""

    def _normalize(value: str | None) -> str | None:
        if value is None:
            return None
        trimmed = value.strip()
        return trimmed or None

    try:
        env_key = _normalize(os.getenv("SECRET_KEY"))
        if env_key:
            return env_key

        import secrets

        candidate_paths = []
        if _normalize(RAILWAY_VOLUME_PATH):
            candidate_paths.append(os.path.join(RAILWAY_VOLUME_PATH, "secret_key.txt"))
        candidate_paths.append(os.path.join(INSTANCE_DIR, "secret_key.txt"))

        # Intentar leer un key ya persistido
        for path in candidate_paths:
            try:
                if os.path.exists(path):
                    with open(path, "r", encoding="utf-8") as fh:
                        key = _normalize(fh.read())
                        if key:
                            os.environ.setdefault("SECRET_KEY", key)
                            print("🔑 SECRET_KEY cargado desde archivo persistente.")
                            return key
            except OSError:
                print(f"⚠️ No se pudo leer SECRET_KEY en {path}; se intentará con otro destino.")

        # Generar y persistir en el primer destino utilizable
        key = secrets.token_hex(32)
        for path in candidate_paths:
            try:
                os.makedirs(os.path.dirname(path), exist_ok=True)
                with open(path, "w", encoding="utf-8") as fh:
                    fh.write(key)
                os.environ.setdefault("SECRET_KEY", key)
                print(
                    "⚠️ SECRET_KEY no está configurado; se generó uno y se guardó en "
                    f"{path}. Usá la variable de entorno SECRET_KEY en producción."
                )
                return key
            except OSError:
                print(
                    "⚠️ SECRET_KEY no está configurado y no se pudo persistir en "
                    f"{path}. Se intentará otro destino."
                )

        print(
            "⚠️ SECRET_KEY no está configurado; se generó uno efímero solo para esta instancia. "
            "Usá la variable de entorno SECRET_KEY en producción."
        )
        os.environ.setdefault("SECRET_KEY", key)
        return key

    except Exception as exc:  # pragma: no cover - salvaguarda defensiva
        import secrets

        fallback = secrets.token_hex(32)
        os.environ.setdefault("SECRET_KEY", fallback)
        print(
            "⚠️ Error inesperado al cargar SECRET_KEY; se usará uno efímero solo para esta instancia.",
            f"Detalle: {exc}",
        )
        return fallback


APP_NAME = "NUR - Notas de Autorización"
ADMIN_ROLE = "admin"
DOP_ROLE = "dop"
OP_ROLE = "operador"
VIEW_ROLE = "visor"

SECRET_KEY = _load_secret_key()

WHATSAPP_NUMBER = os.getenv("WHATSAPP_NUMBER", "")
PUBLIC_WHATSAPP_TEXT = os.getenv(
    "WHATSAPP_TEXT",
    "Hola, cargué mal una nota en el sistema NUR. ¿Me ayudan a corregirla?",
)

# =========================
# DATABASE CONFIG - PERSISTENTE
# =========================

# Configuración para Railway con volumen persistente
# En Railway, configurá un volumen montado en /data
DB_PATH: str | None = None


def _resolve_db_uri() -> tuple[str, str | None, bool]:
    """Devuelve (uri, db_path, using_sqlite) con tolerancia a drivers faltantes."""

    raw = os.getenv("DATABASE_URL")
    if raw:
        db_uri_env = raw.strip()
        if db_uri_env.startswith(("postgres://", "postgresql://")):
            try:
                # Importación explícita para avisar antes de arrancar workers
                import importlib

                importlib.import_module("psycopg2")
                print("🔗 Usando DATABASE_URL (PostgreSQL) provisto por el entorno.")
                return db_uri_env, None, False
            except ImportError:
                print(
                    "⚠️ DATABASE_URL apunta a PostgreSQL pero psycopg2 no está instalado; "
                    "se ignorará y se usará SQLite persistente."
                )
        else:
            # Para otros backends asumimos que el driver está presente
            print("🔗 Usando DATABASE_URL provisto por el entorno.")
            return db_uri_env, None, db_uri_env.startswith("sqlite")

    # SQLite con persistencia
    if os.path.exists(RAILWAY_VOLUME_PATH):
        # En Railway con volumen
        db_path = os.path.join(RAILWAY_VOLUME_PATH, "nur.db")
        print(f"📁 Usando base de datos persistente en: {db_path}")
    else:
        # En local
        os.makedirs(INSTANCE_DIR, exist_ok=True)
        db_path = os.path.join(INSTANCE_DIR, "nur.db")
        print(f"📁 Usando base de datos local en: {db_path}")

    sqlite_uri = "sqlite:///" + db_path.replace("\\", "/")
    return sqlite_uri, db_path, True


SQLALCHEMY_DATABASE_URI, DB_PATH, USING_SQLITE = _resolve_db_uri()


def create_sqlite_backup(db_path: str | None) -> None:
    """Genera un backup puntual de SQLite si existe un archivo previo.

    Esto no reemplaza un backup programado, pero evita perder datos por
    corrupción puntual al arrancar.
    """

    if not db_path:
        return

    try:
        if not os.path.exists(db_path) or os.path.getsize(db_path) == 0:
            return

        backup_dir = os.path.join(os.path.dirname(db_path), "backups")
        os.makedirs(backup_dir, exist_ok=True)
        stamp = datetime.utcnow().strftime("%Y%m%d%H%M%S")
        dest = os.path.join(backup_dir, f"nur-{stamp}.db.bak")
        shutil.copy2(db_path, dest)
        print(f"📦 Backup creado en: {dest}")
    except OSError as exc:
        print(f"⚠️ No se pudo crear backup: {exc}")


create_sqlite_backup(DB_PATH)

# =========================
# App init
# =========================
app = Flask(__name__)
app.config["SECRET_KEY"] = SECRET_KEY
app.config["SQLALCHEMY_DATABASE_URI"] = SQLALCHEMY_DATABASE_URI
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

engine_options = {"pool_pre_ping": True}
if USING_SQLITE:
    engine_options["connect_args"] = {"check_same_thread": False, "timeout": 15}
app.config["SQLALCHEMY_ENGINE_OPTIONS"] = engine_options
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(hours=8)

app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_port=1)

if not _bool_env("FLASK_DEBUG", False):
    app.config.update(
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        REMEMBER_COOKIE_HTTPONLY=True,
        REMEMBER_COOKIE_SAMESITE="Lax",
    )

db = SQLAlchemy(app)
csrf = CSRFProtect(app)
login_manager = LoginManager(app)
login_manager.login_view = "login"
login_manager.login_message = "Tenés que iniciar sesión."


if USING_SQLITE:
    @event.listens_for(Engine, "connect")
    def set_sqlite_pragma(dbapi_connection, connection_record):  # pragma: no cover - configuración
        if not isinstance(dbapi_connection, sqlite3.Connection):
            return
        try:
            cursor = dbapi_connection.cursor()
            cursor.execute("PRAGMA journal_mode=WAL;")
            cursor.execute("PRAGMA synchronous=FULL;")
            cursor.execute("PRAGMA foreign_keys=ON;")
            timeout_ms = _int_env("SQLITE_BUSY_TIMEOUT_MS", 5000)
            cursor.execute(f"PRAGMA busy_timeout={timeout_ms};")
            cursor.close()
        except Exception as exc:  # pragma: no cover - protección defensiva
            print(f"⚠️ No se pudieron aplicar PRAGMA de durabilidad en SQLite: {exc}")

login_attempts = defaultdict(list)

def check_rate_limit(ip: str, max_attempts: int = 10, window_minutes: int = 5) -> bool:
    now = datetime.utcnow()
    cutoff = now - timedelta(minutes=window_minutes)
    login_attempts[ip] = [t for t in login_attempts[ip] if t > cutoff]
    if len(login_attempts[ip]) >= max_attempts:
        return False
    login_attempts[ip].append(now)
    return True


def csrf_field() -> Markup:
    token = generate_csrf()
    return Markup(f'<input type="hidden" name="csrf_token" value="{token}">')

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
    return (raw or "").strip()


def validate_legajo(raw: str) -> tuple[bool, str]:
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


def parse_nro_list(raw: str) -> list[str]:
    """Permite cargar múltiples números de nota separados por ; o ,"""

    cleaned: list[str] = []
    normalized = raw.replace(",", ";")
    for part in normalized.split(";"):
        val = sanitize_text(part, max_len=50)
        if val:
            cleaned.append(val)
    return cleaned


TOP_PUESTOS = [
    "PAMPA",
    "ECO",
    "CARGAS",
    "BRAVO",
    "PREEMBARQUE NACIONAL",
    "PREEMBARQUE INTERNACIONAL",
]


def _normalize_puesto_label(label: str) -> str:
    label = sanitize_text(label, max_len=80)
    if label.upper().startswith("PUESTO "):
        label = label[7:].strip()
    return label.upper()


RAW_PUESTOS = [
    "ADICIONAL OTV",
    "ADICIONAL PARKING RIO",
    "ADICIONAL PROVEEDORES",
    "ADICIONAL TCA",
    "ARRIBOS A2",
    "ARRIBOS ADUANA",
    "ARRIBOS MIGRACIONES",
    "BARRERA CARGAS",
    "C.O.C.",
    "CABECERA NORTE",
    "CABECERA SUR",
    "CALABOZO CARGAS",
    "CALABOZO ECO",
    "CHECKPOINT",
    "COMODORO PY",
    "CONEXIONES ARSA",
    "CONEXIONES INTER",
    "CONEXIONES NACIONALES",
    "CONSIGNA AVIANCA",
    "D.O.C. METROPOLITANA",
    "DEPOSITO VEHICULAR",
    "GAMA",
    "GATE GOURMET",
    "GUARDIA DE PREVENCION",
    "HALL",
    "JET PAQ",
    "MOVIL VUELOS PRIVADOS",
    "OFICINA DE HALLAZGOS",
    "OFICINA RAPSA",
    "OVERZISE",
    "PATIO DE VALIJAS",
    "PATRULLA EXTERNA",
    "PATRULLA PLATAFORMA",
    "PERIMETRO INTERNO ALFA",
    "PORTON AMA",
    "PREEMBARQUE INTERNACIONAL",
    "PREEMBARQUE NACIONAL",
    "PUESTO BRAVO",
    "PUESTO ECO",
    "PUESTO PAMPA",
    "SALA DE ARMAS",
    "TORRE DE CONTROL",
    "TRANSITO VEHICULAR",
    "TURNO LOGISTICA",
    "TURNO OPERACIONES",
    "VUELOS PRIVADOS",
]

_normalized_catalog = []
for puesto in RAW_PUESTOS:
    cleaned = _normalize_puesto_label(puesto)
    if cleaned:
        _normalized_catalog.append(cleaned)

PUESTOS_PREDEFINIDOS = TOP_PUESTOS + [
    p
    for p in sorted(dict.fromkeys(_normalized_catalog))
    if p not in TOP_PUESTOS
]
PUESTOS_PREDEFINIDOS.append("OTRO")


def validate_puesto(raw: str, max_len: int = 50) -> tuple[bool, str]:
    raw = sanitize_text(raw, max_len=max_len)
    if not raw:
        return False, "El puesto es obligatorio."
    if len(raw) < 2:
        return False, "El puesto debe tener al menos 2 caracteres."
    if not re.match(r"^[\w\s\-./]+$", raw):
        return False, "El puesto solo puede tener letras, números, espacios y -./"
    return True, raw


def resolve_puesto_choice(selected: str, otro: str = "") -> tuple[bool, str]:
    raw_input = sanitize_text(selected, max_len=80)
    selected_norm = _normalize_puesto_label(raw_input)
    otro_norm = _normalize_puesto_label(otro)

    if not selected_norm:
        return False, "Elegí un puesto de la lista."

    if selected_norm == "OTRO":
        if not otro_norm:
            return False, "Elegí un puesto o escribí uno en 'Otro'."
        ok, cleaned = validate_puesto(otro_norm)
        return ok, cleaned.upper() if ok else cleaned

    if selected_norm in PUESTOS_PREDEFINIDOS:
        if raw_input and raw_input.upper() != selected_norm:
            return False, f"Puesto no válido. Probá con {selected_norm}."
        return True, selected_norm

    return False, "Puesto no válido. Elegí uno de la lista o seleccioná OTRO."


def puesto_select_component(
    select_name: str = "puesto_predef",
    other_name: str = "puesto_otro",
    selected: str = "",
    other_value: str = "",
) -> str:
    options = "".join([
        f'<option value="{p}">{p}</option>'
        for p in PUESTOS_PREDEFINIDOS
    ])
    show_other = "" if selected == "OTRO" else "style=\"display:none;\""
    preset_value = "" if selected == "OTRO" else selected
    datalist_id = f"lista_{select_name}"
    return f"""
    <div class="form-group">
      <label>Puesto</label>
      <input type="text" name="{select_name}" id="{select_name}" list="{datalist_id}" placeholder="Elegí un puesto" value="{preset_value}" oninput="handlePuestoInput(this, '{other_name}')" onfocus="openPuestoPicker(this)" onclick="openPuestoPicker(this)" autocomplete="off" />
      <datalist id="{datalist_id}">
        <option value="">-- Seleccionar puesto --</option>
        {options}
      </datalist>
      <input type="text" name="{other_name}" id="{other_name}" placeholder="Escribí el puesto" value="{other_value}" {show_other} />
      <p class="small-text">Elegí un puesto de la lista o escribí "OTRO" para completarlo.</p>
    </div>
    """


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


@app.context_processor
def inject_globals():
    return {"APP_NAME": APP_NAME, "csrf_token": generate_csrf}


# =========================
# Bootstrap
# =========================
def bootstrap_users() -> None:
    if User.query.count() > 0:
        return

    admin_user = os.getenv("ADMIN_USER")
    admin_pass = os.getenv("ADMIN_PASS")
    op_user = os.getenv("OP_USER")
    op_pass = os.getenv("OP_PASS")

    if not all([admin_user, admin_pass, op_user, op_pass]):
        import secrets

        admin_user = admin_user or "admin"
        admin_pass = admin_pass or secrets.token_urlsafe(14)
        op_user = op_user or "PSA"
        op_pass = op_pass or secrets.token_urlsafe(12)
        print(
            "⚠️ Credenciales iniciales generadas automáticamente (solo para esta instancia). "
            "Definí ADMIN_USER/ADMIN_PASS/OP_USER/OP_PASS en producción."
        )
        print(f"   ADMIN_USER={admin_user} | ADMIN_PASS={admin_pass}")
        print(f"   OP_USER={op_user} | OP_PASS={op_pass}")

    u1 = User(username=admin_user, role=ADMIN_ROLE)
    u1.set_password(admin_pass)
    u2 = User(username=op_user, role=OP_ROLE)
    u2.set_password(op_pass)

    db.session.add_all([u1, u2])
    db.session.commit()


with app.app_context():
    db.create_all()
    bootstrap_users()
    print(f"✅ Base de datos inicializada correctamente")
    print(f"📊 Usuarios: {User.query.count()} | Notas: {Nota.query.count()} | Errores: {ErrorReporte.query.count()}")


# =========================
# TEMPLATES
# =========================





def render_page(
    title,
    content_html,
    show_admin_nav=False,
    show_dop_nav=False,
    show_op_nav=False,
    show_view_nav=False,
):
    nav_buttons = ""
    if show_admin_nav:
        nav_buttons = f'''
        <a href="{url_for('admin_home')}" class="btn btn-primary">Panel Admin</a>
        <a href="{url_for('admin_usuarios')}" class="btn btn-secondary">Usuarios</a>
        <a href="{url_for('admin_errores')}" class="btn btn-warning">Errores</a>
        '''
    elif show_dop_nav:
        nav_buttons = f'''
        <a href="{url_for('dop_home')}" class="btn btn-primary">Panel DOP</a>
        <a href="{url_for('dop_errores')}" class="btn btn-warning">Errores</a>
        '''
    elif show_op_nav:
        nav_buttons = f'''
        <a href="{url_for('operador_home')}" class="btn btn-primary">Seleccionar Puesto</a>
        <a href="{url_for('operador_reportar_inicio')}" class="btn btn-warning">Reportar ERROR</a>
        '''
    elif show_view_nav:
        nav_buttons = f'''
        <a href="{url_for('visor_home')}" class="btn btn-primary">Notas</a>
        '''

    return render_template(
        "base.html",
        title=title,
        nav_buttons=Markup(nav_buttons),
        content_html=Markup(content_html),
    )

# Continuaré con las rutas en el siguiente mensaje...

# =========================
# Routes
# =========================

@app.route("/")
def index():
    if current_user.is_authenticated:
        if current_user.role == ADMIN_ROLE:
            return redirect(url_for("admin_home"))
        elif current_user.role == DOP_ROLE:
            return redirect(url_for("dop_home"))
        elif current_user.role == OP_ROLE:
            return redirect(url_for("operador_home"))
        else:
            return redirect(url_for("visor_home"))
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        if current_user.role == ADMIN_ROLE:
            return redirect(url_for("admin_home"))
        elif current_user.role == DOP_ROLE:
            return redirect(url_for("dop_home"))
        elif current_user.role == OP_ROLE:
            return redirect(url_for("operador_home"))
        else:
            return redirect(url_for("visor_home"))
    
    if request.method == "POST":
        ip = request.remote_addr
        if not check_rate_limit(ip):
            flash("Demasiados intentos. Esperá unos minutos.", "danger")
            return redirect(url_for("login"))
        
        username = sanitize_text(request.form.get("username", ""))
        password = request.form.get("password", "")
        
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            session.clear()
            session.permanent = True
            login_user(user)
            flash("Bienvenido!", "success")
            
            if user.role == ADMIN_ROLE:
                return redirect(url_for("admin_home"))
            elif user.role == DOP_ROLE:
                return redirect(url_for("dop_home"))
            elif user.role == OP_ROLE:
                return redirect(url_for("operador_home"))
            else:
                return redirect(url_for("visor_home"))
        else:
            flash("Usuario o contraseña incorrectos.", "danger")
    
    return render_template('login.html')


@app.route("/logout", methods=["GET", "POST"])
@login_required
def logout():
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
    flt_nro = request.args.get("nro_nota", "").strip()
    flt_aut = request.args.get("autoriza", "").strip()
    flt_puesto = request.args.get("puesto", "").strip()
    draft_admin = session.pop("draft_admin", {})
    
    q = Nota.query
    if flt_nro:
        q = q.filter(Nota.nro_nota.contains(flt_nro))
    if flt_aut:
        q = q.filter(Nota.autoriza == flt_aut)
    if flt_puesto:
        q = q.filter(Nota.puesto.contains(flt_puesto))

    notas = q.order_by(Nota.id.desc()).limit(250).all()

    catalog_options = "".join([f'<option value="{p}">{p}</option>' for p in PUESTOS_PREDEFINIDOS])

    draft_nro = draft_admin.get("nro_nota", "")
    draft_aut = draft_admin.get("autoriza", "")
    draft_predef = draft_admin.get("puesto_predef", "")
    draft_otro = draft_admin.get("puesto_otro", "")

    content = f"""
<div class="panel panel-highlight">
  <h2>📝 REGISTRAR NOTA</h2>
  <p style="margin-bottom:20px; font-size:15px;">
    Acá prefijás las notas (número, autoriza y puesto). El operador solo completa entrega/recepción.
  </p>
  <p style="margin-bottom:20px; font-size:14px;">
    <strong>Importante:</strong> Podés cargar varios N° separados por <code>;</code> si van al mismo puesto/autoriza.
  </p>
  <form method="POST" action="{url_for('admin_crear_nota')}">
    {csrf_field()}
    <div class="grid">
      <div class="form-group">
        <label>N° Nota</label>
        <input type="text" name="nro_nota" required placeholder="Ej: 9983; 9982; 9992" value="{draft_nro}" />
      </div>
      <div class="form-group">
        <label>Autoriza</label>
        <select name="autoriza" required>
          <option value="">-- Seleccionar --</option>
          <option value="AVSEC" {'selected' if draft_aut=='AVSEC' else ''}>AVSEC</option>
          <option value="OPER" {'selected' if draft_aut=='OPER' else ''}>OPER</option>
        </select>
      </div>
      {puesto_select_component(selected=draft_predef, other_value=draft_otro)}
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
        <input type="text" name="nro_nota" value="{flt_nro}" />
      </div>
      <div class="form-group">
        <label>Filtrar por Autoriza</label>
        <select name="autoriza">
          <option value="">Todos</option>
          <option value="AVSEC" {'selected' if flt_aut=='AVSEC' else ''}>AVSEC</option>
          <option value="OPER" {'selected' if flt_aut=='OPER' else ''}>OPER</option>
        </select>
      </div>
      <div class="form-group">
        <label>Filtrar por Puesto</label>
        <input type="text" name="puesto" value="{flt_puesto}" list="catalog_puestos" placeholder="Escribí o elegí" />
        <datalist id="catalog_puestos">
          <option value="">-- Seleccionar --</option>
          {catalog_options}
        </datalist>
      </div>
    </div>
    <div class="action-row">
      <button type="submit" class="btn btn-primary">🔍 Filtrar</button>
      <a href="{url_for('admin_exportar_csv', nro_nota=flt_nro, autoriza=flt_aut, puesto=flt_puesto)}" class="btn btn-success">📥 Exportar CSV</a>
      <a href="{url_for('admin_home')}" class="btn btn-secondary">🔄 Limpiar filtros</a>
    </div>
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
"""
    
    for n in notas:
        estado_badge = '<span class="badge badge-pending">PENDIENTE</span>' if n.estado == 'PENDIENTE' else '<span class="badge badge-completed">COMPLETADA</span>'
        entrega = f"{n.entrega_nombre or ''} {('('+n.entrega_legajo+')') if n.entrega_legajo else ''}"
        recibe = f"{n.recibe_nombre or ''} {('('+n.recibe_legajo+')') if n.recibe_legajo else ''}"
        recepcion = n.fecha_hora_recepcion.strftime('%d/%m %H:%M') if n.fecha_hora_recepcion else ''
        
        content += f"""
      <tr>
        <td>{n.id}</td>
        <td><strong>{n.nro_nota}</strong></td>
        <td>{n.autoriza}</td>
        <td>{n.puesto}</td>
        <td>{estado_badge}</td>
        <td>{entrega}</td>
        <td>{recibe}</td>
        <td>{recepcion}</td>
        <td>
          <form method="POST" action="{url_for('admin_borrar_nota', nota_id=n.id)}" style="display:inline;"
                onsubmit="return confirm('¿Borrar nota #{n.id}?');">
            {csrf_field()}
            <button type="submit" class="btn btn-danger" style="padding:6px 12px; font-size:12px;">🗑️ Borrar</button>
          </form>
        </td>
      </tr>
"""
    
    content += """
    </tbody>
  </table>
  <p class="small-text" style="margin-top:15px;">Mostrando hasta 250 registros.</p>
</div>
"""
    
    return render_page("Admin - NUR", content, show_admin_nav=True)


@app.route("/admin/crear_nota", methods=["POST"])
@login_required
@role_required(ADMIN_ROLE)
def admin_crear_nota():
    try:
        draft = {
            "nro_nota": request.form.get("nro_nota", ""),
            "autoriza": request.form.get("autoriza", ""),
            "puesto_predef": request.form.get("puesto_predef", ""),
            "puesto_otro": request.form.get("puesto_otro", ""),
        }
        nro_list = parse_nro_list(draft["nro_nota"])
        autoriza = sanitize_text(draft["autoriza"], max_len=10)
        ok_puesto, puesto = resolve_puesto_choice(
            draft["puesto_predef"],
            draft["puesto_otro"],
        )
        if not ok_puesto:
            session["draft_admin"] = draft
            session.modified = True
            flash(puesto, "danger")
            return redirect(url_for("admin_home"))

        if not nro_list or not autoriza or not puesto:
            session["draft_admin"] = draft
            session.modified = True
            flash("Todos los campos son obligatorios.", "danger")
            return redirect(url_for("admin_home"))

        if autoriza not in ["AVSEC", "OPER"]:
            session["draft_admin"] = draft
            session.modified = True
            flash("Autoriza debe ser AVSEC u OPER.", "danger")
            return redirect(url_for("admin_home"))

        for nro in nro_list:
            nota = Nota(
                nro_nota=nro,
                autoriza=autoriza,
                puesto=puesto,
                estado="PENDIENTE",
                creado_por=current_user.username
            )
            db.session.add(nota)

        db.session.commit()

        session.pop("draft_admin", None)
        flash(f"Notas creadas: {', '.join(nro_list)} - {puesto}", "success")
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
        
        notas = q.limit(10000).all()
        
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
    known_passwords = session.get("known_passwords", {}) if isinstance(session.get("known_passwords", {}), dict) else {}
    
    content = f"""
<div class="panel">
  <h2>👥 Gestión de Usuarios</h2>
  <p style="margin-bottom:20px;">
    Creá usuarios con diferentes roles: <strong>Admin</strong> (control total), <strong>DOP</strong> (carga notas y ve todo, sin borrar), <strong>Operador</strong> (completa notas).
  </p>

  <form method="POST" action="{url_for('admin_crear_usuario')}" style="margin-bottom:30px;">
    {csrf_field()}
    <div class="grid">
      <div class="form-group">
        <label>Nombre de usuario</label>
        <input type="text" name="username" required />
      </div>
      <div class="form-group">
        <label>Contraseña</label>
        <div class="password-wrapper">
          <input type="password" name="password" id="admin-new-password" required />
          <button type="button" class="toggle-pass" onclick="togglePasswordVisibility('admin-new-password', this)" aria-label="Mostrar u ocultar contraseña">👁️</button>
        </div>
      </div>
      <div class="form-group">
        <label>Rol</label>
        <select name="role" required>
          <option value="operador">Operador (completa notas)</option>
          <option value="dop">DOP (carga notas, solo lectura)</option>
          <option value="visor">Visor (solo lectura de notas)</option>
          <option value="admin">Admin (control total)</option>
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
        <th>Contraseña</th>
        <th>Acciones</th>
      </tr>
    </thead>
    <tbody>
"""
    
    for u in usuarios:
        content += f"""
      <tr>
        <td>{u.username}</td>
        <td><span class="badge badge-completed">{u.role.upper()}</span></td>
        <td>
          <div class="password-plain">{Markup.escape(known_passwords.get(str(u.id), '')) or '<span class="muted">No disponible</span>'}</div>
        </td>
        <td class="user-actions">
          <form method="POST" action="{url_for('admin_reset_password', user_id=u.id)}" style="display:inline;" onsubmit="return confirm('¿Generar una nueva contraseña para {u.username}?');">
            {csrf_field()}
            <button type="submit" class="btn btn-warning" style="padding:6px 12px; font-size:12px;">🔄 Reset/Mostrar</button>
          </form>
          <form method="POST" action="{url_for('admin_borrar_usuario', user_id=u.id)}" style="display:inline;"
                onsubmit="return confirm('¿Borrar usuario {u.username}?');">
            {csrf_field()}
            <button type="submit" class="btn btn-danger" style="padding:6px 12px; font-size:12px;">🗑️ Borrar</button>
          </form>
        </td>
      </tr>
"""
    
    content += """
    </tbody>
  </table>
</div>
"""
    
    return render_page("Usuarios - Admin", content, show_admin_nav=True)


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
        
        if role not in [ADMIN_ROLE, DOP_ROLE, OP_ROLE, VIEW_ROLE]:
            flash("Rol inválido.", "danger")
            return redirect(url_for("admin_usuarios"))
        
        if User.query.filter_by(username=username).first():
            flash(f"Usuario '{username}' ya existe.", "warning")
            return redirect(url_for("admin_usuarios"))
        
        user = User(username=username, role=role)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()

        known_pw = session.get("known_passwords", {}) if isinstance(session.get("known_passwords", {}), dict) else {}
        known_pw[str(user.id)] = password
        session["known_passwords"] = known_pw
        session.modified = True
        
        flash(f"Usuario '{username}' creado con rol {role.upper()}.", "success")
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


@app.route("/admin/reset_password/<int:user_id>", methods=["POST"])
@login_required
@role_required(ADMIN_ROLE)
def admin_reset_password(user_id: int):
    try:
        user = db.session.get(User, user_id)
        if not user:
            flash("Usuario no encontrado.", "danger")
            return redirect(url_for("admin_usuarios"))

        new_pass = secrets.token_urlsafe(12)
        user.set_password(new_pass)
        db.session.commit()

        known_pw = session.get("known_passwords", {}) if isinstance(session.get("known_passwords", {}), dict) else {}
        known_pw[str(user.id)] = new_pass
        session["known_passwords"] = known_pw
        session.modified = True

        flash(f"Nueva contraseña para {user.username}: {new_pass}", "success")
    except Exception as e:
        db.session.rollback()
        flash(f"Error al resetear contraseña: {str(e)}", "danger")

    return redirect(url_for("admin_usuarios"))


@app.route("/admin/errores")
@login_required
@role_required(ADMIN_ROLE)
def admin_errores():
    """Panel de errores con modal para ver detalle completo"""
    errores = ErrorReporte.query.order_by(ErrorReporte.creado_en.desc()).limit(200).all()
    
    content = f"""
<div class="panel">
  <h2>🚨 Reportes de Errores</h2>
  
  <table>
    <thead>
      <tr>
        <th>ID</th>
        <th>N° Nota</th>
        <th>Puesto</th>
        <th>Reportado por</th>
        <th>Detalle (resumen)</th>
        <th>Fecha</th>
        <th>Estado</th>
        <th>Acciones</th>
      </tr>
    </thead>
    <tbody>
"""
    
    for e in errores:
        estado_badge = '<span class="badge badge-open">ABIERTO</span>' if e.estado == 'ABIERTO' else '<span class="badge badge-closed">CERRADO</span>'
        cerrar_btn = ""
        if e.estado == "ABIERTO":
            cerrar_btn = (
                f'<form method="POST" action="{url_for("admin_cerrar_error", err_id=e.id)}" style="display:inline;">'
                f"{csrf_field()}"
                f'<button type="submit" class="btn btn-success" style="padding:6px 12px; font-size:12px;">✅ Cerrar</button>'
                f"</form>"
            )
        
        # Escapar HTML para el modal
        detalle_escapado = e.detalle.replace("'", "\\'").replace('"', '&quot;').replace('\n', '\\n')
        
        content += f"""
      <tr>
        <td>{e.id}</td>
        <td>{e.nro_nota or '-'}</td>
        <td>{e.puesto or '-'}</td>
        <td>{e.reportado_por}</td>
        <td>{e.detalle[:50]}...</td>
        <td>{e.creado_en.strftime('%d/%m %H:%M')}</td>
        <td>{estado_badge}</td>
        <td>
          <button onclick="openModal({e.id}, '{e.nro_nota or '-'}', '{e.puesto or '-'}', '{e.reportado_por}', '{detalle_escapado}', '{e.creado_en.strftime('%d/%m/%Y %H:%M')}', '{e.estado}')" class="btn btn-primary" style="padding:6px 12px; font-size:12px;">👁️ Ver</button>
          {cerrar_btn}
          <form method="POST" action="{url_for('admin_borrar_error', err_id=e.id)}" style="display:inline;"
                onsubmit="return confirm('¿Borrar reporte #{e.id}?');">
            {csrf_field()}
            <button type="submit" class="btn btn-danger" style="padding:6px 12px; font-size:12px;">🗑️ Borrar</button>
          </form>
        </td>
      </tr>
"""
    
    content += """
    </tbody>
  </table>
  <p class="small-text" style="margin-top:15px;">Mostrando hasta 200 registros.</p>
</div>

<!-- Modal -->
<div id="errorModal" class="modal">
  <div class="modal-content">
    <div class="modal-header">
      <h2>📋 Detalle del Reporte de Error</h2>
      <span class="close" onclick="closeModal()">&times;</span>
    </div>
    <div class="modal-body">
      <div class="modal-field">
        <div class="modal-field-label">ID del Reporte</div>
        <div class="modal-field-value" id="modal-id"></div>
      </div>
      <div class="modal-field">
        <div class="modal-field-label">N° de Nota</div>
        <div class="modal-field-value" id="modal-nro-nota"></div>
      </div>
      <div class="modal-field">
        <div class="modal-field-label">Puesto</div>
        <div class="modal-field-value" id="modal-puesto"></div>
      </div>
      <div class="modal-field">
        <div class="modal-field-label">Reportado por</div>
        <div class="modal-field-value" id="modal-reportado"></div>
      </div>
      <div class="modal-field">
        <div class="modal-field-label">Fecha y Hora</div>
        <div class="modal-field-value" id="modal-fecha"></div>
      </div>
      <div class="modal-field">
        <div class="modal-field-label">Estado</div>
        <div class="modal-field-value" id="modal-estado"></div>
      </div>
      <div class="modal-field">
        <div class="modal-field-label">Detalle Completo del Problema</div>
        <div class="modal-field-value" id="modal-detalle" style="background:#f9fafb; padding:15px; border-radius:6px; border-left:4px solid #2563eb;"></div>
      </div>
    </div>
  </div>
</div>

<script>
function openModal(id, nroNota, puesto, reportado, detalle, fecha, estado) {
  document.getElementById('modal-id').textContent = '#' + id;
  document.getElementById('modal-nro-nota').textContent = nroNota;
  document.getElementById('modal-puesto').textContent = puesto;
  document.getElementById('modal-reportado').textContent = reportado;
  document.getElementById('modal-fecha').textContent = fecha;
  document.getElementById('modal-estado').innerHTML = estado === 'ABIERTO' 
    ? '<span class="badge badge-open">ABIERTO</span>' 
    : '<span class="badge badge-closed">CERRADO</span>';
  document.getElementById('modal-detalle').textContent = detalle;
  document.getElementById('errorModal').style.display = 'block';
}

function closeModal() {
  document.getElementById('errorModal').style.display = 'none';
}

window.onclick = function(event) {
  const modal = document.getElementById('errorModal');
  if (event.target == modal) {
    closeModal();
  }
}

document.addEventListener('keydown', function(event) {
  if (event.key === 'Escape') {
    closeModal();
  }
});
</script>
"""
    
    return render_page("Errores - Admin", content, show_admin_nav=True)


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
        db.session.commit()
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
# Visor (solo lectura) Routes
# =========================


@app.route("/visor")
@login_required
@role_required(VIEW_ROLE)
def visor_home():
    flt_nro = request.args.get("nro_nota", "").strip()
    flt_aut = request.args.get("autoriza", "").strip()
    flt_puesto = request.args.get("puesto", "").strip()
    flt_estado = request.args.get("estado", "").strip().upper()

    q = Nota.query
    if flt_nro:
        q = q.filter(Nota.nro_nota.contains(flt_nro))
    if flt_aut:
        q = q.filter(Nota.autoriza == flt_aut)
    if flt_puesto:
        q = q.filter(Nota.puesto.contains(flt_puesto))
    if flt_estado:
        q = q.filter(Nota.estado == flt_estado)

    notas = q.order_by(Nota.id.desc()).limit(300).all()

    rows = "".join(
        [
            f"""
        <tr>
          <td>{n.nro_nota}</td>
          <td>{n.autoriza}</td>
          <td>{n.puesto}</td>
          <td><span class='badge badge-state {n.estado.lower()}'>{n.estado}</span></td>
          <td>{n.entrega_nombre or '-'}<br/><span class='small-text'>{n.entrega_legajo or ''}</span></td>
          <td>{n.recibe_nombre or '-'}<br/><span class='small-text'>{n.recibe_legajo or ''}</span></td>
          <td>{n.completado_en.strftime('%d/%m/%Y %H:%M') if n.completado_en else '-'}</td>
        </tr>
        """
            for n in notas
        ]
    )

    catalog_options = "".join([f'<option value="{p}">{p}</option>' for p in PUESTOS_PREDEFINIDOS])

    content = f"""
<div class="panel">
  <h2>📋 Notas (solo lectura)</h2>
  <p class="small-text">Filtrá por número, autoriza, puesto o estado. Máx 300 resultados.</p>
  <form method="GET" class="grid" style="margin-top:15px; gap:16px;">
    <div class="form-group">
      <label>N° Nota</label>
      <input type="text" name="nro_nota" value="{flt_nro}" placeholder="Ej: 1234" />
    </div>
    <div class="form-group">
      <label>Autoriza</label>
      <select name="autoriza">
        <option value="">Todos</option>
        <option value="AVSEC" {'selected' if flt_aut=='AVSEC' else ''}>AVSEC</option>
        <option value="OPER" {'selected' if flt_aut=='OPER' else ''}>OPER</option>
      </select>
    </div>
    <div class="form-group">
      <label>Puesto</label>
      <input type="text" name="puesto" value="{flt_puesto}" list="catalog_puestos" placeholder="Ej: GATE A1" />
      <datalist id="catalog_puestos">
        <option value="">-- Seleccionar --</option>
        {catalog_options}
      </datalist>
    </div>
    <div class="form-group">
      <label>Estado</label>
      <select name="estado">
        <option value="" {'selected' if not flt_estado else ''}>Todos</option>
        <option value="PENDIENTE" {'selected' if flt_estado=='PENDIENTE' else ''}>Pendiente</option>
        <option value="COMPLETADO" {'selected' if flt_estado=='COMPLETADO' else ''}>Completado</option>
      </select>
    </div>
    <div style="display:flex; gap:10px; align-items:flex-end;">
      <button type="submit" class="btn btn-primary">🔍 Aplicar filtros</button>
      <a class="btn btn-secondary" href="{url_for('visor_home')}">Limpiar</a>
    </div>
  </form>
  <table>
    <thead>
      <tr>
        <th>N° Nota</th>
        <th>Autoriza</th>
        <th>Puesto</th>
        <th>Estado</th>
        <th>Entrega</th>
        <th>Recibe</th>
        <th>Completado en</th>
      </tr>
    </thead>
    <tbody>
      {rows or '<tr><td colspan="7">Sin resultados</td></tr>'}
    </tbody>
  </table>
</div>
"""

    return render_page("Visor - NUR", content, show_view_nav=True)


# Continúa con DOP y Operador en el siguiente mensaje...
# =========================
# DOP Routes (Director de Operaciones)
# =========================

@app.route("/dop")
@login_required
@role_required(DOP_ROLE)
def dop_home():
    """Panel DOP - puede crear notas y ver todo, pero NO borrar"""
    flt_nro = request.args.get("nro_nota", "").strip()
    flt_aut = request.args.get("autoriza", "").strip()
    flt_puesto = request.args.get("puesto", "").strip()
    draft_dop = session.pop("draft_dop", {})
    
    q = Nota.query
    if flt_nro:
        q = q.filter(Nota.nro_nota.contains(flt_nro))
    if flt_aut:
        q = q.filter(Nota.autoriza == flt_aut)
    if flt_puesto:
        q = q.filter(Nota.puesto.contains(flt_puesto))

    notas = q.order_by(Nota.id.desc()).limit(250).all()

    catalog_options = "".join([f'<option value="{p}">{p}</option>' for p in PUESTOS_PREDEFINIDOS])

    draft_nro = draft_dop.get("nro_nota", "")
    draft_aut = draft_dop.get("autoriza", "")
    draft_predef = draft_dop.get("puesto_predef", "")
    draft_otro = draft_dop.get("puesto_otro", "")

    content = f"""
<div class="panel panel-highlight">
  <h2>📝 REGISTRAR NOTA</h2>
  <p style="margin-bottom:20px; font-size:15px;">
    Acá prefijás las notas (número, autoriza y puesto). El operador solo completa entrega/recepción.
  </p>
  <p style="margin-bottom:20px; font-size:14px;">
    <strong>Importante:</strong> Podés cargar varios N° separados por <code>;</code> si van al mismo puesto/autoriza.
  </p>
  <form method="POST" action="{url_for('dop_crear_nota')}">
    {csrf_field()}
    <div class="grid">
      <div class="form-group">
        <label>N° Nota</label>
        <input type="text" name="nro_nota" required placeholder="Ej: 9983; 9982; 9992" value="{draft_nro}" />
      </div>
      <div class="form-group">
        <label>Autoriza</label>
        <select name="autoriza" required>
          <option value="">-- Seleccionar --</option>
          <option value="AVSEC" {'selected' if draft_aut=='AVSEC' else ''}>AVSEC</option>
          <option value="OPER" {'selected' if draft_aut=='OPER' else ''}>OPER</option>
        </select>
      </div>
      {puesto_select_component(selected=draft_predef, other_value=draft_otro)}
    </div>
    <button type="submit" class="btn btn-success" style="width:100%; font-size:16px;">✅ Crear Nota</button>
  </form>
</div>

<div class="panel">
  <h2>📋 Notas Registradas (Solo Lectura)</h2>
  <form method="GET" style="margin-bottom:20px;">
    <div class="grid">
      <div class="form-group">
        <label>Filtrar por N° Nota</label>
        <input type="text" name="nro_nota" value="{flt_nro}" />
      </div>
      <div class="form-group">
        <label>Filtrar por Autoriza</label>
        <select name="autoriza">
          <option value="">Todos</option>
          <option value="AVSEC" {'selected' if flt_aut=='AVSEC' else ''}>AVSEC</option>
          <option value="OPER" {'selected' if flt_aut=='OPER' else ''}>OPER</option>
        </select>
      </div>
      <div class="form-group">
        <label>Filtrar por Puesto</label>
        <input type="text" name="puesto" value="{flt_puesto}" list="catalog_puestos_dop" />
        <datalist id="catalog_puestos_dop">
          <option value="">-- Seleccionar --</option>
          {catalog_options}
        </datalist>
      </div>
    </div>
    <button type="submit" class="btn btn-primary">🔍 Filtrar</button>
    <a href="{url_for('dop_exportar_csv', nro_nota=flt_nro, autoriza=flt_aut, puesto=flt_puesto)}" class="btn btn-success">📥 Exportar CSV</a>
    <a href="{url_for('dop_home')}" class="btn btn-secondary">🔄 Limpiar filtros</a>
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
      </tr>
    </thead>
    <tbody>
"""
    
    for n in notas:
        estado_badge = '<span class="badge badge-pending">PENDIENTE</span>' if n.estado == 'PENDIENTE' else '<span class="badge badge-completed">COMPLETADA</span>'
        entrega = f"{n.entrega_nombre or ''} {('('+n.entrega_legajo+')') if n.entrega_legajo else ''}"
        recibe = f"{n.recibe_nombre or ''} {('('+n.recibe_legajo+')') if n.recibe_legajo else ''}"
        recepcion = n.fecha_hora_recepcion.strftime('%d/%m %H:%M') if n.fecha_hora_recepcion else ''
        
        content += f"""
      <tr>
        <td>{n.id}</td>
        <td><strong>{n.nro_nota}</strong></td>
        <td>{n.autoriza}</td>
        <td>{n.puesto}</td>
        <td>{estado_badge}</td>
        <td>{entrega}</td>
        <td>{recibe}</td>
        <td>{recepcion}</td>
      </tr>
"""
    
    content += """
    </tbody>
  </table>
  <p class="small-text" style="margin-top:15px;">Mostrando hasta 250 registros. (Solo lectura - no podés borrar)</p>
</div>
"""
    
    return render_page("DOP - NUR", content, show_dop_nav=True)


@app.route("/dop/crear_nota", methods=["POST"])
@login_required
@role_required(DOP_ROLE)
def dop_crear_nota():
    try:
        draft = {
            "nro_nota": request.form.get("nro_nota", ""),
            "autoriza": request.form.get("autoriza", ""),
            "puesto_predef": request.form.get("puesto_predef", ""),
            "puesto_otro": request.form.get("puesto_otro", ""),
        }
        nro_list = parse_nro_list(draft["nro_nota"])
        autoriza = sanitize_text(draft["autoriza"], max_len=10)
        ok_puesto, puesto = resolve_puesto_choice(
            draft["puesto_predef"],
            draft["puesto_otro"],
        )
        if not ok_puesto:
            session["draft_dop"] = draft
            session.modified = True
            flash(puesto, "danger")
            return redirect(url_for("dop_home"))

        if not nro_list or not autoriza or not puesto:
            session["draft_dop"] = draft
            session.modified = True
            flash("Todos los campos son obligatorios.", "danger")
            return redirect(url_for("dop_home"))

        if autoriza not in ["AVSEC", "OPER"]:
            session["draft_dop"] = draft
            session.modified = True
            flash("Autoriza debe ser AVSEC u OPER.", "danger")
            return redirect(url_for("dop_home"))

        for nro in nro_list:
            nota = Nota(
                nro_nota=nro,
                autoriza=autoriza,
                puesto=puesto,
                estado="PENDIENTE",
                creado_por=current_user.username
            )
            db.session.add(nota)

        db.session.commit()

        session.pop("draft_dop", None)
        flash(f"Notas creadas: {', '.join(nro_list)} - {puesto}", "success")
    except Exception as e:
        db.session.rollback()
        flash(f"Error al crear nota: {str(e)}", "danger")
    
    return redirect(url_for("dop_home"))


@app.route("/dop/exportar_csv")
@login_required
@role_required(DOP_ROLE)
def dop_exportar_csv():
    try:
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
        
        notas = q.limit(10000).all()
        
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
        return redirect(url_for("dop_home"))


@app.route("/dop/errores")
@login_required
@role_required(DOP_ROLE)
def dop_errores():
    """Panel de errores para DOP - solo lectura con modal"""
    errores = ErrorReporte.query.order_by(ErrorReporte.creado_en.desc()).limit(200).all()
    
    content = f"""
<div class="panel">
  <h2>🚨 Reportes de Errores (Solo Lectura)</h2>
  <p style="margin-bottom:20px; font-size:14px; color:#6b7280;">
    Podés ver los reportes pero no cerrarlos ni borrarlos. Solo el Admin puede gestionarlos.
  </p>
  
  <table>
    <thead>
      <tr>
        <th>ID</th>
        <th>N° Nota</th>
        <th>Puesto</th>
        <th>Reportado por</th>
        <th>Detalle (resumen)</th>
        <th>Fecha</th>
        <th>Estado</th>
        <th>Acciones</th>
      </tr>
    </thead>
    <tbody>
"""
    
    for e in errores:
        estado_badge = '<span class="badge badge-open">ABIERTO</span>' if e.estado == 'ABIERTO' else '<span class="badge badge-closed">CERRADO</span>'
        detalle_escapado = e.detalle.replace("'", "\\'").replace('"', '&quot;').replace('\n', '\\n')
        
        content += f"""
      <tr>
        <td>{e.id}</td>
        <td>{e.nro_nota or '-'}</td>
        <td>{e.puesto or '-'}</td>
        <td>{e.reportado_por}</td>
        <td>{e.detalle[:50]}...</td>
        <td>{e.creado_en.strftime('%d/%m %H:%M')}</td>
        <td>{estado_badge}</td>
        <td>
          <button onclick="openModal({e.id}, '{e.nro_nota or '-'}', '{e.puesto or '-'}', '{e.reportado_por}', '{detalle_escapado}', '{e.creado_en.strftime('%d/%m/%Y %H:%M')}', '{e.estado}')" class="btn btn-primary" style="padding:6px 12px; font-size:12px;">👁️ Ver</button>
        </td>
      </tr>
"""
    
    content += """
    </tbody>
  </table>
  <p class="small-text" style="margin-top:15px;">Mostrando hasta 200 registros.</p>
</div>

<!-- Modal -->
<div id="errorModal" class="modal">
  <div class="modal-content">
    <div class="modal-header">
      <h2>📋 Detalle del Reporte de Error</h2>
      <span class="close" onclick="closeModal()">&times;</span>
    </div>
    <div class="modal-body">
      <div class="modal-field">
        <div class="modal-field-label">ID del Reporte</div>
        <div class="modal-field-value" id="modal-id"></div>
      </div>
      <div class="modal-field">
        <div class="modal-field-label">N° de Nota</div>
        <div class="modal-field-value" id="modal-nro-nota"></div>
      </div>
      <div class="modal-field">
        <div class="modal-field-label">Puesto</div>
        <div class="modal-field-value" id="modal-puesto"></div>
      </div>
      <div class="modal-field">
        <div class="modal-field-label">Reportado por</div>
        <div class="modal-field-value" id="modal-reportado"></div>
      </div>
      <div class="modal-field">
        <div class="modal-field-label">Fecha y Hora</div>
        <div class="modal-field-value" id="modal-fecha"></div>
      </div>
      <div class="modal-field">
        <div class="modal-field-label">Estado</div>
        <div class="modal-field-value" id="modal-estado"></div>
      </div>
      <div class="modal-field">
        <div class="modal-field-label">Detalle Completo del Problema</div>
        <div class="modal-field-value" id="modal-detalle" style="background:#f9fafb; padding:15px; border-radius:6px; border-left:4px solid #2563eb;"></div>
      </div>
    </div>
  </div>
</div>

<script>
function openModal(id, nroNota, puesto, reportado, detalle, fecha, estado) {
  document.getElementById('modal-id').textContent = '#' + id;
  document.getElementById('modal-nro-nota').textContent = nroNota;
  document.getElementById('modal-puesto').textContent = puesto;
  document.getElementById('modal-reportado').textContent = reportado;
  document.getElementById('modal-fecha').textContent = fecha;
  document.getElementById('modal-estado').innerHTML = estado === 'ABIERTO' 
    ? '<span class="badge badge-open">ABIERTO</span>' 
    : '<span class="badge badge-closed">CERRADO</span>';
  document.getElementById('modal-detalle').textContent = detalle;
  document.getElementById('errorModal').style.display = 'block';
}

function closeModal() {
  document.getElementById('errorModal').style.display = 'none';
}

window.onclick = function(event) {
  const modal = document.getElementById('errorModal');
  if (event.target == modal) {
    closeModal();
  }
}

document.addEventListener('keydown', function(event) {
  if (event.key === 'Escape') {
    closeModal();
  }
});
</script>
"""
    
    return render_page("Errores - DOP", content, show_dop_nav=True)


# =========================
# Operador Routes
# =========================

@app.route("/operador")
@login_required
@role_required(OP_ROLE)
def operador_home():
    puestos = db.session.query(Nota.puesto).filter_by(estado="PENDIENTE").distinct().order_by(Nota.puesto).all()
    puestos = [p[0] for p in puestos]
    
    options = "".join([f'<option value="{p}">{p}</option>' for p in puestos])
    
    content = f"""
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
    <select id="selectPuesto">
      <option value="">-- Seleccionar puesto --</option>
      {options}
    </select>
  </div>
  <button onclick="irPuesto()" class="btn btn-primary">📂 Ver Notas del Puesto</button>
</div>

<script>
function irPuesto() {{
  const p = document.getElementById('selectPuesto').value;
  if (!p) {{ alert('Seleccioná un puesto'); return; }}
  window.location.href = "/operador/puesto/" + encodeURIComponent(p);
}}
</script>
"""
    
    return render_page("Operador - NUR", content, show_op_nav=True)


@app.route("/operador/puesto/<puesto>")
@login_required
@role_required(OP_ROLE)
def operador_puesto(puesto: str):
    ok_puesto, puesto = validate_puesto(puesto)
    if not ok_puesto:
        flash(puesto, "danger")
        return redirect(url_for("operador_home"))

    notas = Nota.query.filter_by(puesto=puesto, estado="PENDIENTE").order_by(Nota.id).all()

    content = f"""
<div class="panel">
  <h2>📋 Puesto: {puesto}</h2>
  <p style="margin-bottom:20px;">
    Seleccioná una nota pendiente y completala. Dentro de la nota vas a poder marcar si querés conservar los datos de entrega/recepción durante esta sesión.
  </p>
  <p style="margin-bottom:20px; font-size:13px; color:#dc2626;">
    <strong>⚠️ Importante:</strong> Si el legajo tiene puntos o comas (ej: 501.123 o 501,123), va a dar error: usá solo números.
  </p>
</div>
"""
    
    if notas:
        content += f"""
<div class="panel">
  <h2>📝 Notas Pendientes ({len(notas)})</h2>
  <div class="table-responsive">
    <table class="responsive-table">
      <thead>
        <tr>
          <th>ID</th>
          <th>N° Nota</th>
          <th>Autoriza</th>
          <th>Acciones</th>
        </tr>
      </thead>
      <tbody>
"""
        for n in notas:
            content += f"""
      <tr>
        <td data-label="ID">{n.id}</td>
        <td data-label="N° Nota"><strong>{n.nro_nota}</strong></td>
        <td data-label="Autoriza">{n.autoriza}</td>
        <td data-label="Acciones">
          <a href="{url_for('operador_completar_nota', nota_id=n.id)}" class="btn btn-primary" style="padding:6px 12px; font-size:12px; width:100%; text-align:center;">✏️ Completar</a>
        </td>
      </tr>
"""
        content += """
      </tbody>
    </table>
  </div>
</div>
"""
    else:
        content += """
<div class="alert alert-warning">
  ✅ No hay notas pendientes para este puesto.
</div>
"""
    
    content += f'<a href="{url_for("operador_home")}" class="btn btn-secondary">← Volver a selección de puesto</a>'
    
    return render_page(f"Puesto {puesto} - Operador", content, show_op_nav=True)


@app.route("/operador/completar/<int:nota_id>", methods=["GET", "POST"])
@login_required
@role_required(OP_ROLE)
def operador_completar_nota(nota_id: int):
    nota = db.session.get(Nota, nota_id)
    if not nota:
        flash("Nota no encontrada.", "danger")
        return redirect(url_for("operador_home"))
    
    if nota.estado != "PENDIENTE":
        flash("Esta nota ya fue completada.", "warning")
        return redirect(url_for("operador_puesto", puesto=nota.puesto))
    
    session_key = f"defaults_{nota.puesto}"
    pre = dict(session.get(session_key, {}))
    remember_prefill = "checked" if pre else ""
    field_errors: dict[str, str] = {}

    if request.method == "POST":
        try:
            entrega_nombre = sanitize_text(request.form.get("entrega_nombre", ""))
            entrega_legajo = normalize_legajo(request.form.get("entrega_legajo", ""))
            recibe_nombre = sanitize_text(request.form.get("recibe_nombre", ""))
            recibe_legajo = normalize_legajo(request.form.get("recibe_legajo", ""))
            remember_defaults = request.form.get("remember_defaults") == "on"
            fecha_str = request.form.get("fecha_hora_recepcion", "")
            observaciones = sanitize_text(request.form.get("observaciones", ""), max_len=500)

            pre.update({
                "entrega_nombre": entrega_nombre,
                "entrega_legajo": entrega_legajo,
                "recibe_nombre": recibe_nombre,
                "recibe_legajo": recibe_legajo,
                "fecha_hora_recepcion": fecha_str,
                "observaciones": observaciones,
            })
            remember_prefill = "checked" if remember_defaults or pre else ""

            if not entrega_nombre:
                field_errors["entrega_nombre"] = "Ingresá el nombre de quien entrega."
            if not recibe_nombre:
                field_errors["recibe_nombre"] = "Ingresá el nombre de quien recibe."
            if not fecha_str:
                field_errors["fecha_hora_recepcion"] = "Ingresá fecha y hora de recepción."

            ok_ent, msg_ent = validate_legajo(entrega_legajo)
            if not ok_ent:
                field_errors["entrega_legajo"] = msg_ent

            ok_rec, msg_rec = validate_legajo(recibe_legajo)
            if not ok_rec:
                field_errors["recibe_legajo"] = msg_rec

            try:
                fecha_hora = datetime.fromisoformat(fecha_str)
            except ValueError:
                field_errors["fecha_hora_recepcion"] = "Formato de fecha inválido."

            if field_errors:
                flash("Corregí los campos marcados en rojo.", "danger")
                raise ValueError("Errores de validación")

            nota.entrega_nombre = entrega_nombre
            nota.entrega_legajo = entrega_legajo
            nota.recibe_nombre = recibe_nombre
            nota.recibe_legajo = recibe_legajo
            nota.fecha_hora_recepcion = fecha_hora
            nota.observaciones = observaciones
            nota.estado = "COMPLETADA"
            nota.completado_por = current_user.username
            nota.completado_en = datetime.utcnow()

            if remember_defaults:
                session[session_key] = {
                    "entrega_nombre": entrega_nombre,
                    "entrega_legajo": entrega_legajo,
                    "recibe_nombre": recibe_nombre,
                    "recibe_legajo": recibe_legajo,
                }
            else:
                session.pop(session_key, None)
            session.modified = True

            db.session.commit()
            flash(f"✅ Nota #{nota_id} completada.", "success")
            
            return redirect(url_for("operador_puesto", puesto=nota.puesto))
            
        except Exception as e:
            db.session.rollback()
            if not field_errors:
                flash(f"Error al completar: {str(e)}", "danger")

    entrega_legajo_err = field_errors.get("entrega_legajo", "")
    recibe_legajo_err = field_errors.get("recibe_legajo", "")
    entrega_nombre_err = field_errors.get("entrega_nombre", "")
    recibe_nombre_err = field_errors.get("recibe_nombre", "")
    fecha_err = field_errors.get("fecha_hora_recepcion", "")

    def _err(cls: str) -> str:
        return " invalid" if cls else ""

    content = f"""
<div class="panel">
  <h2>✏️ Completar Nota #{nota.id}</h2>
  <p><strong>N° Nota:</strong> {nota.nro_nota} | <strong>Autoriza:</strong> {nota.autoriza} | <strong>Puesto:</strong> {nota.puesto}</p>
</div>

<div class="panel">
  <form method="POST" class="stacked-form">
    {csrf_field()}
    <div class="form-group">
      <label>Entrega - Nombre y Apellido</label>
      <input type="text" name="entrega_nombre" class="{_err(entrega_nombre_err)}" value="{pre.get('entrega_nombre', '')}" required placeholder="Nombre y Apellido" />
      {f'<p class="error-text">{entrega_nombre_err}</p>' if entrega_nombre_err else ''}
    </div>
    <div class="form-group">
      <label>Entrega - Legajo</label>
      <input type="text" name="entrega_legajo" class="{_err(entrega_legajo_err)}" value="{pre.get('entrega_legajo', '')}" required placeholder="Ej: 501123" />
      {f'<p class="error-text">{entrega_legajo_err}</p>' if entrega_legajo_err else '<p class="small-text">Usá solo números (501000 - 512000).</p>'}
    </div>
    <div class="form-group">
      <label>Recibe - Nombre y Apellido</label>
      <input type="text" name="recibe_nombre" class="{_err(recibe_nombre_err)}" value="{pre.get('recibe_nombre', '')}" required placeholder="Nombre y Apellido" />
      {f'<p class="error-text">{recibe_nombre_err}</p>' if recibe_nombre_err else ''}
    </div>
    <div class="form-group">
      <label>Recibe - Legajo</label>
      <input type="text" name="recibe_legajo" class="{_err(recibe_legajo_err)}" value="{pre.get('recibe_legajo', '')}" required placeholder="Ej: 502456" />
      {f'<p class="error-text">{recibe_legajo_err}</p>' if recibe_legajo_err else '<p class="small-text">Usá solo números (501000 - 512000).</p>'}
    </div>
    <div class="form-group">
      <label>Fecha y Hora de Recepción</label>
      <input type="datetime-local" name="fecha_hora_recepcion" class="{_err(fecha_err)}" value="{pre.get('fecha_hora_recepcion', '')}" required />
      {f'<p class="error-text">{fecha_err}</p>' if fecha_err else ''}
    </div>
    <div class="form-group">
      <label>Observaciones (opcional)</label>
      <textarea name="observaciones" rows="3">{pre.get('observaciones', '')}</textarea>
    </div>
    <label class="remember-toggle">
      <input type="checkbox" name="remember_defaults" {remember_prefill} />
      Guardar datos de entrega y recepción para esta sesión
    </label>
    <div class="action-row">
      <button type="submit" class="btn btn-success">✅ Completar Nota</button>
      <a href="{url_for('operador_puesto', puesto=nota.puesto)}" class="btn btn-secondary">← Cancelar</a>
    </div>
  </form>
</div>
"""
    
    return render_page(f"Completar Nota #{nota_id}", content, show_op_nav=True)


@app.route("/operador/reportar_inicio")
@login_required
@role_required(OP_ROLE)
def operador_reportar_inicio():
    """Formulario mejorado para reportar errores con selección de N° de Nota y Puesto"""

    notas_recientes = Nota.query.order_by(Nota.id.desc()).limit(100).all()

    nros_nota = sorted(set([n.nro_nota for n in notas_recientes]))
    puestos = sorted(set([n.puesto for n in notas_recientes]) | set(PUESTOS_PREDEFINIDOS))
    
    nro_options = "".join([f'<option value="{nro}">{nro}</option>' for nro in nros_nota])
    puesto_options = "".join([f'<option value="{p}">{p}</option>' for p in puestos])
    
    wsp_link = None
    if WHATSAPP_NUMBER:
        import urllib.parse
        wsp_link = f"https://wa.me/{WHATSAPP_NUMBER}?text={urllib.parse.quote(PUBLIC_WHATSAPP_TEXT)}"
    
    wsp_button = f'<p style="margin-bottom:20px;">También podés contactar por WhatsApp: <a href="{wsp_link}" target="_blank" class="btn btn-success">📱 WhatsApp</a></p>' if wsp_link else ''
    
    content = f"""
<div class="panel">
  <h2>🚨 Reportar Error</h2>
  <p style="margin-bottom:20px;">
    Si completaste mal una nota, reportalo acá. Seleccioná el N° de Nota y Puesto, y describí el problema.
  </p>
  {wsp_button}
</div>

<div class="panel">
  <form method="POST" action="{url_for('operador_reportar')}">
    {csrf_field()}
    <div class="grid">
      <div class="form-group">
        <label>N° de Nota (seleccioná o escribí)</label>
        <input list="nros_nota_list" name="nro_nota" placeholder="Seleccioná o escribí el N° de nota">
        <datalist id="nros_nota_list">
          <option value="">-- Seleccionar --</option>
          {nro_options}
        </datalist>
        <p class="small-text">Podés seleccionar de la lista o escribir manualmente si no aparece.</p>
      </div>
      
      <div class="form-group">
        <label>Puesto (seleccioná o escribí)</label>
        <input list="puestos_list" name="puesto" placeholder="Seleccioná o escribí el puesto">
        <datalist id="puestos_list">
          <option value="">-- Seleccionar --</option>
          {puesto_options}
        </datalist>
        <p class="small-text">Podés seleccionar de la lista o escribir manualmente si no aparece.</p>
      </div>
    </div>
    
    <div class="form-group">
      <label>Detalle del problema</label>
      <textarea name="detalle" rows="5" required placeholder="Describí qué cargaste mal o qué necesitás corregir..."></textarea>
    </div>
    
    <button type="submit" class="btn btn-danger">📤 Enviar Reporte</button>
    <a href="{url_for('operador_home')}" class="btn btn-secondary">← Cancelar</a>
  </form>
</div>

<style>
input[list] {{
  background-image: url('data:image/svg+xml;utf8,<svg fill="gray" height="24" viewBox="0 0 24 24" width="24" xmlns="http://www.w3.org/2000/svg"><path d="M7 10l5 5 5-5z"/></svg>');
  background-repeat: no-repeat;
  background-position: right 10px center;
  background-size: 20px;
  cursor: pointer;
}}
</style>
"""
    
    return render_page("Reportar Error", content, show_op_nav=True)


@app.route("/operador/reportar", methods=["POST"])
@login_required
@role_required(OP_ROLE)
def operador_reportar():
    try:
        nro_nota = sanitize_text(request.form.get("nro_nota", ""), max_len=50)
        raw_puesto = request.form.get("puesto", "")
        puesto = ""
        if raw_puesto:
            ok_puesto, puesto = validate_puesto(raw_puesto)
            if not ok_puesto:
                flash(puesto, "danger")
                return redirect(url_for("operador_reportar_inicio"))
        detalle = sanitize_text(request.form.get("detalle", ""), max_len=1000)
        
        if not detalle:
            flash("El detalle es obligatorio.", "danger")
            return redirect(url_for("operador_reportar_inicio"))
        
        nota = None
        if nro_nota and puesto:
            nota = Nota.query.filter_by(nro_nota=nro_nota, puesto=puesto).first()
        
        err = ErrorReporte(
            nota_id=nota.id if nota else None,
            nro_nota=nro_nota or None,
            puesto=puesto or None,
            reportado_por=current_user.username,
            detalle=detalle
        )
        db.session.add(err)
        db.session.commit()
        
        flash("✅ Reporte enviado. El admin lo revisará.", "success")
        return redirect(url_for("operador_home"))
            
    except Exception as e:
        db.session.rollback()
        flash(f"Error al enviar reporte: {str(e)}", "danger")
        return redirect(url_for("operador_reportar_inicio"))


# =========================
# Error Handlers
# =========================

@app.errorhandler(403)
def forbidden(e):
    return "<h1>403 - No tenés permisos</h1><a href='/'>Volver</a>", 403


@app.errorhandler(404)
def not_found(e):
    return "<h1>404 - Página no encontrada</h1><a href='/'>Volver</a>", 404


@app.errorhandler(500)
def internal_error(e):
    db.session.rollback()
    return "<h1>500 - Error interno del servidor</h1><a href='/'>Volver</a>", 500


def export_tables_to_csv(out_dir: str | None = None) -> list[str]:
    """Exporta tablas clave a CSV sin iniciar el servidor web."""

    default_dir = out_dir
    if not default_dir:
        if os.path.exists(RAILWAY_VOLUME_PATH):
            default_dir = os.path.join(RAILWAY_VOLUME_PATH, "backups")
        else:
            default_dir = os.path.join(INSTANCE_DIR, "backups")

    os.makedirs(default_dir, exist_ok=True)
    stamp = datetime.utcnow().strftime("%Y%m%d%H%M%S")
    nota_path = os.path.join(default_dir, f"notas-{stamp}.csv")
    err_path = os.path.join(default_dir, f"errores-{stamp}.csv")

    def _fmt(dt_val):
        return dt_val.isoformat() if dt_val else ""

    with app.app_context():
        notas = Nota.query.order_by(Nota.id).all()
        with open(nota_path, "w", newline="", encoding="utf-8") as fh:
            writer = csv.writer(fh)
            writer.writerow([
                "ID", "NroNota", "Autoriza", "Puesto", "Estado",
                "EntregaNombre", "EntregaLegajo",
                "RecibeNombre", "RecibeLegajo",
                "FechaHoraRecepcion", "Observaciones",
                "CreadoPor", "CreadoEn", "CompletadoPor", "CompletadoEn",
            ])
            for n in notas:
                writer.writerow([
                    n.id, n.nro_nota, n.autoriza, n.puesto, n.estado,
                    n.entrega_nombre or "", n.entrega_legajo or "",
                    n.recibe_nombre or "", n.recibe_legajo or "",
                    _fmt(n.fecha_hora_recepcion), n.observaciones or "",
                    n.creado_por or "", _fmt(n.creado_en),
                    n.completado_por or "", _fmt(n.completado_en),
                ])

        errores = ErrorReporte.query.order_by(ErrorReporte.id).all()
        with open(err_path, "w", newline="", encoding="utf-8") as fh:
            writer = csv.writer(fh)
            writer.writerow([
                "ID", "NotaID", "NroNota", "Puesto", "ReportadoPor",
                "Detalle", "CreadoEn", "Estado",
            ])
            for err in errores:
                writer.writerow([
                    err.id, err.nota_id or "", err.nro_nota or "",
                    err.puesto or "", err.reportado_por or "",
                    err.detalle or "", _fmt(err.creado_en), err.estado or "",
                ])

    return [nota_path, err_path]


# =========================
# Run
# =========================
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="NUR utility runner")
    parser.add_argument("--export-csv", action="store_true", help="Exporta tablas a CSV y sale")
    parser.add_argument("--out-dir", help="Directorio destino para los CSV y backups", default=None)
    args = parser.parse_args()

    if args.export_csv:
        paths = export_tables_to_csv(args.out_dir)
        for p in paths:
            print(f"📤 CSV generado en: {p}")
    else:
        port = int(os.getenv("PORT", 5000))
        debug = _bool_env("FLASK_DEBUG", False)
        app.run(host="0.0.0.0", port=port, debug=debug)
