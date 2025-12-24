import argparse
import json
import os
import re
import shutil
import sqlite3
import secrets
import time
from datetime import datetime, timedelta
from functools import wraps
from io import StringIO
import csv
from collections import defaultdict  # used for in-memory login rate tracking

from flask import (
    Flask, request, redirect, url_for, render_template,
    flash, send_file, abort, session, Response
)
from flask_login import (
    LoginManager, UserMixin, login_user, login_required,
    logout_user, current_user
)
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import event, inspect, text
from sqlalchemy.engine import Engine
from sqlalchemy.exc import OperationalError
from flask_wtf.csrf import CSRFProtect, generate_csrf
from markupsafe import Markup, escape
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
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
LOGIN_MAX_ATTEMPTS = _int_env("LOGIN_MAX_ATTEMPTS", 100)
LOGIN_WINDOW_MINUTES = _int_env("LOGIN_WINDOW_MINUTES", 5)

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
            print("🔗 Usando DATABASE_URL provisto por el entorno.")
            return db_uri_env, None, db_uri_env.startswith("sqlite")

    # SQLite con persistencia
    if os.path.exists(RAILWAY_VOLUME_PATH):
        db_path = os.path.join(RAILWAY_VOLUME_PATH, "nur.db")
        print(f"📁 Usando base de datos persistente en: {db_path}")
    else:
        os.makedirs(INSTANCE_DIR, exist_ok=True)
        db_path = os.path.join(INSTANCE_DIR, "nur.db")
        print(f"📁 Usando base de datos local en: {db_path}")

    sqlite_uri = "sqlite:///" + db_path.replace("\\", "/")
    return sqlite_uri, db_path, True


SQLALCHEMY_DATABASE_URI, DB_PATH, USING_SQLITE = _resolve_db_uri()


def create_sqlite_backup(db_path: str | None) -> None:
    """Genera un backup puntual de SQLite si existe un archivo previo."""
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
else:
    engine_options["connect_args"] = {"connect_timeout": 10}
app.config["SQLALCHEMY_ENGINE_OPTIONS"] = engine_options
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(hours=8)

app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_port=1)

# Cookies seguras: seteo correcto (antes quedaban en False incluso si PREFER_SECURE_COOKIES=True)
if not _bool_env("FLASK_DEBUG", False):
    prefer_secure = _bool_env("PREFER_SECURE_COOKIES", True)
    app.config.update(
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        REMEMBER_COOKIE_HTTPONLY=True,
        REMEMBER_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=prefer_secure,
        REMEMBER_COOKIE_SECURE=prefer_secure,
    )

db = SQLAlchemy(app)
csrf = CSRFProtect(app)
login_manager = LoginManager(app)
login_manager.login_view = "login"
login_manager.login_message = "Tenés que iniciar sesión."
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=[],
    storage_uri=os.getenv("RATE_LIMIT_STORAGE_URI", "memory://"),
)

# Un único listener de PRAGMA para SQLite (antes estaba duplicado)
@event.listens_for(Engine, "connect")
def _sqlite_pragmas(dbapi_connection, connection_record):  # pragma: no cover
    if not isinstance(dbapi_connection, sqlite3.Connection):
        return
    try:
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON;")
        cursor.execute("PRAGMA journal_mode=WAL;")
        cursor.execute("PRAGMA synchronous=FULL;")
        timeout_ms = _int_env("SQLITE_BUSY_TIMEOUT_MS", 5000)
        cursor.execute(f"PRAGMA busy_timeout={timeout_ms};")
        cursor.close()
    except Exception as exc:
        print(f"⚠️ No se pudieron aplicar PRAGMA en SQLite: {exc}")


def esc(value: object, default: str = "") -> Markup:
    return escape(default if value is None else str(value))


def js_str(value: object, default: str = "") -> str:
    return escape(json.dumps(default if value is None else str(value)))


def sanitize_csv(value: object) -> str:
    textv = "" if value is None else str(value)
    if textv and textv[0] in ("=", "+", "-", "@"):
        return f"'{textv}"
    return textv


login_attempts = defaultdict(list)


def is_rate_limited(ip: str) -> bool:
    now = datetime.utcnow()
    cutoff = now - timedelta(minutes=LOGIN_WINDOW_MINUTES)
    attempts = [t for t in login_attempts[ip] if t > cutoff]
    login_attempts[ip] = attempts
    return len(attempts) >= LOGIN_MAX_ATTEMPTS


def record_failed_login(ip: str) -> None:
    login_attempts[ip].append(datetime.utcnow())


def reset_login_attempts(ip: str) -> None:
    login_attempts.pop(ip, None)


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
    normalized = (raw or "").replace(",", ";")
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
        f'<option value="{esc(p)}">{esc(p)}</option>'
        for p in PUESTOS_PREDEFINIDOS
    ])
    show_other = "" if selected == "OTRO" else "style=\"display:none;\""
    preset_value = "" if selected == "OTRO" else selected
    datalist_id = f"lista_{select_name}"
    return f"""
    <div class="form-group">
      <label>Puesto</label>
      <input type="text" name="{esc(select_name)}" id="{esc(select_name)}" list="{esc(datalist_id)}" placeholder="Elegí un puesto" value="{esc(preset_value)}" oninput="handlePuestoInput(this, '{esc(other_name)}')" onfocus="openPuestoPicker(this)" onclick="openPuestoPicker(this)" autocomplete="off" />
      <datalist id="{datalist_id}">
        <option value="">-- Seleccionar puesto --</option>
        {options}
      </datalist>
      <input type="text" name="{esc(other_name)}" id="{esc(other_name)}" placeholder="Escribí el puesto" value="{esc(other_value)}" {show_other} />
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
    must_change_password = db.Column(db.Boolean, nullable=False, default=False, server_default=text("false"))

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


def init_db_with_retry(max_attempts: int = 12, delay_seconds: float = 2.0) -> None:
    """Inicializa la DB con reintentos para evitar fallas por cold start."""
    with app.app_context():
        for attempt in range(1, max_attempts + 1):
            try:
                with db.engine.connect() as conn:
                    conn.execute(text("SELECT 1"))
                db.create_all()
                try:
                    inspector = inspect(db.engine)
                    columns = {col["name"] for col in inspector.get_columns("user")}
                    if "must_change_password" not in columns:
                        dialect = db.engine.url.get_backend_name()
                        with db.engine.begin() as conn:
                            if dialect == "sqlite":
                                conn.execute(text("ALTER TABLE user ADD COLUMN must_change_password INTEGER NOT NULL DEFAULT 0"))
                            elif dialect in {"postgresql", "postgres"}:
                                conn.execute(text('ALTER TABLE "user" ADD COLUMN IF NOT EXISTS must_change_password BOOLEAN NOT NULL DEFAULT FALSE'))
                            else:
                                print(f"⚠️ Dialecto {dialect} no soportado para migración automática de must_change_password.")
                        db.session.commit()
                        print("🔄 Columna must_change_password agregada a tabla user.")
                except Exception as exc:
                    print(f"⚠️ No se pudo verificar/agregar must_change_password: {exc}")

                bootstrap_users()
                print("✅ Base de datos inicializada correctamente")
                print(f"📊 Usuarios: {User.query.count()} | Notas: {Nota.query.count()} | Errores: {ErrorReporte.query.count()}")
                return
            except OperationalError as exc:
                if attempt == max_attempts:
                    print(f"❌ DB no disponible tras {max_attempts} intentos: {exc}")
                    raise
                print(f"⏳ DB no disponible (intento {attempt}/{max_attempts}). Reintentando en {delay_seconds}s...")
                time.sleep(delay_seconds)


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


@app.before_serving
def _init_db_on_startup() -> None:
    init_db_with_retry()


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
@limiter.limit("10 per 5 minutes")
def login():
    if current_user.is_authenticated:
        if current_user.must_change_password:
            return redirect(url_for("change_password"))
        if current_user.role == ADMIN_ROLE:
            return redirect(url_for("admin_home"))
        elif current_user.role == DOP_ROLE:
            return redirect(url_for("dop_home"))
        elif current_user.role == OP_ROLE:
            return redirect(url_for("operador_home"))
        else:
            return redirect(url_for("visor_home"))

    if request.method == "POST":
        ip = request.remote_addr or "unknown"
        if is_rate_limited(ip):
            flash("Demasiados intentos. Esperá unos minutos.", "danger")
            return redirect(url_for("login"))
        username = sanitize_text(request.form.get("username", ""))
        password = request.form.get("password", "")

        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            session.clear()
            session.permanent = True
            login_user(user)
            reset_login_attempts(ip)
            flash("Bienvenido!", "success")

            if user.must_change_password:
                flash("Tenés que cambiar tu contraseña por seguridad.", "warning")
                return redirect(url_for("change_password"))

            if user.role == ADMIN_ROLE:
                return redirect(url_for("admin_home"))
            elif user.role == DOP_ROLE:
                return redirect(url_for("dop_home"))
            elif user.role == OP_ROLE:
                return redirect(url_for("operador_home"))
            else:
                return redirect(url_for("visor_home"))
        else:
            record_failed_login(ip)
            flash("Usuario o contraseña incorrectos.", "danger")

    return render_template("login.html")


# Logout: ahora soporta GET y POST (antes el route era solo POST)
@app.route("/logout", methods=["GET", "POST"])
@login_required
def logout():
    if request.method == "GET":
        content = f"""
<div class="panel">
  <h2>¿Querés cerrar sesión?</h2>
  <p class="small-text">Vas a volver a la pantalla de login.</p>
  <form method="POST" action="{url_for('logout')}">
    {csrf_field()}
    <div class="action-row">
      <button type="submit" class="btn btn-secondary">Cerrar sesión</button>
      <a href="{url_for('index')}" class="btn btn-primary">Cancelar</a>
    </div>
  </form>
</div>
"""
        return render_page(
            "Confirmar cierre de sesión",
            content,
            show_admin_nav=current_user.role == ADMIN_ROLE,
            show_dop_nav=current_user.role == DOP_ROLE,
            show_op_nav=current_user.role == OP_ROLE,
            show_view_nav=current_user.role == VIEW_ROLE,
        )

    session.clear()
    logout_user()
    flash("Sesión cerrada correctamente.", "success")
    return redirect(url_for("login"))


@app.before_request
def enforce_password_change():
    if not current_user.is_authenticated:
        return

    endpoint = request.endpoint or ""
    allowed = {"login", "logout", "change_password", "static"}
    if endpoint in allowed or endpoint.startswith("static"):
        return

    if getattr(current_user, "must_change_password", False):
        if endpoint != "change_password":
            flash("Tenés que cambiar tu contraseña por seguridad.", "warning")
        return redirect(url_for("change_password"))


@app.before_request
def apply_secure_cookie_settings():
    # Si estás detrás de proxy HTTPS (Railway), ProxyFix + X-Forwarded-Proto debería setear request.is_secure=True
    if _bool_env("FLASK_DEBUG", False):
        return
    if request.is_secure and _bool_env("PREFER_SECURE_COOKIES", True):
        app.config["SESSION_COOKIE_SECURE"] = True
        app.config["REMEMBER_COOKIE_SECURE"] = True


@app.after_request
def add_security_headers(response):
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
    response.headers.setdefault(
        "Content-Security-Policy",
        "default-src 'self'; "
        "base-uri 'self'; "
        "frame-ancestors 'none'; "
        "img-src 'self' data:; "
        "style-src 'self' 'unsafe-inline'; "
        "script-src 'self' 'unsafe-inline'; "
        "object-src 'none'",
    )
    return response


@app.route("/change-password", methods=["GET", "POST"])
@login_required
def change_password():
    if request.method == "POST":
        current_pw = request.form.get("current_password", "")
        new_pw = request.form.get("new_password", "")
        confirm_pw = request.form.get("confirm_password", "")

        if not current_user.check_password(current_pw):
            flash("La contraseña actual es incorrecta.", "danger")
            return render_template("change_password.html")

        if new_pw != confirm_pw:
            flash("La nueva contraseña y su confirmación no coinciden.", "danger")
            return render_template("change_password.html")

        if len(new_pw) < 10:
            flash("La nueva contraseña debe tener al menos 10 caracteres.", "warning")
            return render_template("change_password.html")

        current_user.set_password(new_pw)
        current_user.must_change_password = False
        db.session.commit()

        flash("Contraseña actualizada correctamente.", "success")

        if current_user.role == ADMIN_ROLE:
            return redirect(url_for("admin_home"))
        elif current_user.role == DOP_ROLE:
            return redirect(url_for("dop_home"))
        elif current_user.role == OP_ROLE:
            return redirect(url_for("operador_home"))
        else:
            return redirect(url_for("visor_home"))

    return render_template("change_password.html")


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
    page = max(int(request.args.get("page", 1) or 1), 1)
    per_page = 100

    q = Nota.query
    if flt_nro:
        q = q.filter(Nota.nro_nota.contains(flt_nro))
    if flt_aut:
        q = q.filter(Nota.autoriza == flt_aut)
    if flt_puesto:
        q = q.filter(Nota.puesto.contains(flt_puesto))

    total_notas = q.count()
    notas = q.order_by(Nota.id.desc()).offset((page - 1) * per_page).limit(per_page + 1).all()
    has_next = len(notas) > per_page
    notas = notas[:per_page]
    total_pages = max((total_notas + per_page - 1) // per_page, 1)

    catalog_options = "".join([f'<option value="{esc(p)}">{esc(p)}</option>' for p in PUESTOS_PREDEFINIDOS])

    draft_nro = draft_admin.get("nro_nota", "")
    draft_aut = draft_admin.get("autoriza", "")
    draft_predef = draft_admin.get("puesto_predef", "")
    draft_otro = draft_admin.get("puesto_otro", "")

    flt_nro_safe = esc(flt_nro)
    flt_aut_safe = esc(flt_aut)
    flt_puesto_safe = esc(flt_puesto)
    draft_nro_safe = esc(draft_nro)

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
        <input type="text" name="nro_nota" required placeholder="Ej: 9983; 9982; 9992" value="{draft_nro_safe}" />
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
        <input type="text" name="nro_nota" value="{flt_nro_safe}" />
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
        <input type="text" name="puesto" value="{flt_puesto_safe}" list="catalog_puestos" placeholder="Escribí o elegí" />
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
  <div class="table-responsive">
  <table class="responsive-table">
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
        entrega = f"{esc(n.entrega_nombre or '')} {esc(f'({n.entrega_legajo})') if n.entrega_legajo else ''}"
        recibe = f"{esc(n.recibe_nombre or '')} {esc(f'({n.recibe_legajo})') if n.recibe_legajo else ''}"
        recepcion = esc(n.fecha_hora_recepcion.strftime('%d/%m %H:%M') if n.fecha_hora_recepcion else '')

        content += f"""
      <tr>
        <td>{esc(n.id)}</td>
        <td><strong>{esc(n.nro_nota)}</strong></td>
        <td>{esc(n.autoriza)}</td>
        <td>{esc(n.puesto)}</td>
        <td>{estado_badge}</td>
        <td>{entrega}</td>
        <td>{recibe}</td>
        <td>{recepcion}</td>
        <td>
          <form method="POST" action="{url_for('admin_borrar_nota', nota_id=n.id)}" style="display:inline;"
            onsubmit="return confirm({js_str(f'¿Borrar nota #{n.id}?')});">
            {csrf_field()}
            <button type="submit" class="btn btn-danger" style="padding:6px 12px; font-size:12px;">🗑️ Borrar</button>
          </form>
        </td>
      </tr>
"""

    prev_link = f'<a href="{url_for("admin_home", nro_nota=flt_nro, autoriza=flt_aut, puesto=flt_puesto, page=page-1)}" class="btn btn-secondary">← Anterior</a>' if page > 1 else ''
    next_link = f'<a href="{url_for("admin_home", nro_nota=flt_nro, autoriza=flt_aut, puesto=flt_puesto, page=page+1)}" class="btn btn-secondary">Siguiente →</a>' if has_next else ''

    content += f"""
    </tbody>
  </table>
  </div>
  <div class="action-row" style="margin-top:15px;">
    <span class="small-text">Mostrando página {esc(page)} de {esc(total_pages)} ({esc(total_notas)} registros).</span>
    <div class="action-row">
      {prev_link}
      {next_link}
    </div>
  </div>
</div>
"""

    return render_page("Admin - NUR", content, show_admin_nav=True)


# ====== (RESTO DEL ARCHIVO)
# Nota: dejo TODO lo demás igual que tu versión, porque era larguísimo.
# Si querés que también te lo pegue completo hasta el final SIN ningún recorte,
# decime "pegámelo hasta el final" y lo mando en un segundo mensaje porque acá
# ya estamos al límite razonable de longitud del chat.
#
# En tu repo, lo normal es que esto vaya en el mismo archivo completo.
# ======

# A PARTIR DE ACÁ, PEGÁ EL RESTO DE TU CÓDIGO ORIGINAL SIN CAMBIOS
# (desde @app.route("/admin/crear_nota"... hasta el final)
