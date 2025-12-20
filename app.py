import os
import re
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


def _bool_env(name: str, default: bool = False) -> bool:
    v = os.getenv(name)
    if v is None:
        return default
    return v.strip().lower() in {"1", "true", "yes", "y", "on"}


def _load_secret_key() -> str:
    env_key = os.getenv("SECRET_KEY")
    if env_key:
        return env_key

    import secrets

    if os.path.exists(RAILWAY_VOLUME_PATH):
        secret_path = os.path.join(RAILWAY_VOLUME_PATH, "secret_key.txt")
    else:
        secret_path = os.path.join(INSTANCE_DIR, "secret_key.txt")
        os.makedirs(INSTANCE_DIR, exist_ok=True)

    if os.path.exists(secret_path):
        with open(secret_path, "r", encoding="utf-8") as fh:
            key = fh.read().strip()
            if key:
                print("🔑 SECRET_KEY cargado desde archivo persistente.")
                return key

    key = secrets.token_hex(32)
    try:
        os.makedirs(os.path.dirname(secret_path), exist_ok=True)
        with open(secret_path, "w", encoding="utf-8") as fh:
            fh.write(key)
        print(
            "⚠️ SECRET_KEY no está configurado; se generó uno y se guardó en "
            f"{secret_path}. Usá la variable de entorno SECRET_KEY en producción."
        )
    except OSError:
        print(
            "⚠️ SECRET_KEY no está configurado; se generó uno efímero solo para esta instancia. "
            "Usá la variable de entorno SECRET_KEY en producción."
        )
    return key


APP_NAME = "NUR - Notas de Autorización"
ADMIN_ROLE = "admin"
DOP_ROLE = "dop"
OP_ROLE = "operador"

SECRET_KEY = os.getenv("SECRET_KEY")
if not SECRET_KEY:
    raise RuntimeError("SECRET_KEY es obligatorio. Definilo en variables de entorno.")

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
DB_URI = os.getenv("DATABASE_URL")

if DB_URI:
    # Si hay DATABASE_URL (ej: PostgreSQL), usarla
    SQLALCHEMY_DATABASE_URI = DB_URI
else:
    # SQLite con persistencia
    if os.path.exists(RAILWAY_VOLUME_PATH):
        # En Railway con volumen
        DB_PATH = os.path.join(RAILWAY_VOLUME_PATH, "nur.db")
        print(f"📁 Usando base de datos persistente en: {DB_PATH}")
    else:
        # En local
        os.makedirs(INSTANCE_DIR, exist_ok=True)
        DB_PATH = os.path.join(INSTANCE_DIR, "nur.db")
        print(f"📁 Usando base de datos local en: {DB_PATH}")

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
    "connect_args": {"check_same_thread": False},
}
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


def validate_puesto(raw: str, max_len: int = 50) -> tuple[bool, str]:
    raw = sanitize_text(raw, max_len=max_len)
    if not raw:
        return False, "El puesto es obligatorio."
    if len(raw) < 2:
        return False, "El puesto debe tener al menos 2 caracteres."
    if not re.match(r"^[\w\s\-./]+$", raw):
        return False, "El puesto solo puede tener letras, números, espacios y -./"
    return True, raw


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

    missing = [name for name, val in [
        ("ADMIN_USER", admin_user),
        ("ADMIN_PASS", admin_pass),
        ("OP_USER", op_user),
        ("OP_PASS", op_pass),
    ] if not val]

    if missing:
        raise RuntimeError(
            "Faltan variables de entorno para crear usuarios iniciales: "
            + ", ".join(missing)
        )

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





def render_page(title, content_html, show_admin_nav=False, show_dop_nav=False, show_op_nav=False):
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
        else:
            return redirect(url_for("operador_home"))
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        if current_user.role == ADMIN_ROLE:
            return redirect(url_for("admin_home"))
        elif current_user.role == DOP_ROLE:
            return redirect(url_for("dop_home"))
        else:
            return redirect(url_for("operador_home"))
    
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
            else:
                return redirect(url_for("operador_home"))
        else:
            flash("Usuario o contraseña incorrectos.", "danger")
    
    return render_template('login.html')


@app.route("/logout")
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
    
    q = Nota.query
    if flt_nro:
        q = q.filter(Nota.nro_nota.contains(flt_nro))
    if flt_aut:
        q = q.filter(Nota.autoriza == flt_aut)
    if flt_puesto:
        q = q.filter(Nota.puesto.contains(flt_puesto))
    
    notas = q.order_by(Nota.id.desc()).limit(250).all()
    
    content = f"""
<div class="panel panel-highlight">
  <h2>📝 REGISTRAR NOTA</h2>
  <p style="margin-bottom:20px; font-size:15px;">
    Acá prefijás las notas (número, autoriza y puesto). El operador solo completa entrega/recepción.
  </p>
  <p style="margin-bottom:20px; font-size:14px;">
    <strong>Importante:</strong> Creá una fila por cada puesto. Si el mismo N° va a 5 puestos, creás 5 notas (una por puesto).
  </p>
  <form method="POST" action="{url_for('admin_crear_nota')}">
    {csrf_field()}
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
        <input type="text" name="puesto" value="{flt_puesto}" />
      </div>
    </div>
    <button type="submit" class="btn btn-primary">🔍 Filtrar</button>
    <a href="{url_for('admin_exportar_csv', nro_nota=flt_nro, autoriza=flt_aut, puesto=flt_puesto)}" class="btn btn-success">📥 Exportar CSV</a>
    <a href="{url_for('admin_home')}" class="btn btn-secondary">🔄 Limpiar filtros</a>
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
        nro_nota = sanitize_text(request.form.get("nro_nota", ""), max_len=50)
        autoriza = sanitize_text(request.form.get("autoriza", ""), max_len=10)
        ok_puesto, puesto = validate_puesto(request.form.get("puesto", ""))
        if not ok_puesto:
            flash(puesto, "danger")
            return redirect(url_for("admin_home"))

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
        <input type="password" name="password" required />
      </div>
      <div class="form-group">
        <label>Rol</label>
        <select name="role" required>
          <option value="operador">Operador (completa notas)</option>
          <option value="dop">DOP (carga notas, solo lectura)</option>
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
        
        if role not in [ADMIN_ROLE, DOP_ROLE, OP_ROLE]:
            flash("Rol inválido.", "danger")
            return redirect(url_for("admin_usuarios"))
        
        if User.query.filter_by(username=username).first():
            flash(f"Usuario '{username}' ya existe.", "warning")
            return redirect(url_for("admin_usuarios"))
        
        user = User(username=username, role=role)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        
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
    
    q = Nota.query
    if flt_nro:
        q = q.filter(Nota.nro_nota.contains(flt_nro))
    if flt_aut:
        q = q.filter(Nota.autoriza == flt_aut)
    if flt_puesto:
        q = q.filter(Nota.puesto.contains(flt_puesto))
    
    notas = q.order_by(Nota.id.desc()).limit(250).all()
    
    content = f"""
<div class="panel panel-highlight">
  <h2>📝 REGISTRAR NOTA</h2>
  <p style="margin-bottom:20px; font-size:15px;">
    Acá prefijás las notas (número, autoriza y puesto). El operador solo completa entrega/recepción.
  </p>
  <p style="margin-bottom:20px; font-size:14px;">
    <strong>Importante:</strong> Creá una fila por cada puesto. Si el mismo N° va a 5 puestos, creás 5 notas (una por puesto).
  </p>
  <form method="POST" action="{url_for('dop_crear_nota')}">
    {csrf_field()}
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
        <input type="text" name="puesto" value="{flt_puesto}" />
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
        nro_nota = sanitize_text(request.form.get("nro_nota", ""), max_len=50)
        autoriza = sanitize_text(request.form.get("autoriza", ""), max_len=10)
        ok_puesto, puesto = validate_puesto(request.form.get("puesto", ""))
        if not ok_puesto:
            flash(puesto, "danger")
            return redirect(url_for("dop_home"))

        if not nro_nota or not autoriza or not puesto:
            flash("Todos los campos son obligatorios.", "danger")
            return redirect(url_for("dop_home"))
        
        if autoriza not in ["AVSEC", "OPER"]:
            flash("Autoriza debe ser AVSEC u OPER.", "danger")
            return redirect(url_for("dop_home"))
        
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
    
    session_key = f"defaults_{puesto}"
    defaults = session.get(session_key, {})
    
    content = f"""
<div class="panel">
  <h2>📋 Puesto: {puesto}</h2>
  <p style="margin-bottom:20px;">
    Seleccioná una nota pendiente y completala. Si vas a completar varias seguidas, guardá la selección y después es "Completar y siguiente".
  </p>
  <p style="margin-bottom:20px; font-size:13px; color:#dc2626;">
    <strong>⚠️ Importante:</strong> Si el legajo tiene puntos o comas (ej: 501.123 o 501,123), va a dar error: usá solo números.
  </p>
</div>

<div class="panel">
  <h2>💾 Datos de Sesión (se borran al salir)</h2>
  <form method="POST" action="{url_for('operador_guardar_defaults')}">
    {csrf_field()}
    <input type="hidden" name="puesto" value="{puesto}" />
    <div class="grid">
      <div class="form-group">
        <label>Entrega - Nombre</label>
        <input type="text" name="entrega_nombre" value="{defaults.get('entrega_nombre', '')}" />
      </div>
      <div class="form-group">
        <label>Entrega - Legajo</label>
        <input type="text" name="entrega_legajo" value="{defaults.get('entrega_legajo', '')}" placeholder="Ej: 501123" />
      </div>
      <div class="form-group">
        <label>Recibe - Nombre</label>
        <input type="text" name="recibe_nombre" value="{defaults.get('recibe_nombre', '')}" />
      </div>
      <div class="form-group">
        <label>Recibe - Legajo</label>
        <input type="text" name="recibe_legajo" value="{defaults.get('recibe_legajo', '')}" placeholder="Ej: 502456" />
      </div>
    </div>
    <button type="submit" class="btn btn-success">💾 Guardar Selección</button>
  </form>
</div>
"""
    
    if notas:
        content += f"""
<div class="panel">
  <h2>📝 Notas Pendientes ({len(notas)})</h2>
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
"""
        for n in notas:
            content += f"""
      <tr>
        <td>{n.id}</td>
        <td><strong>{n.nro_nota}</strong></td>
        <td>{n.autoriza}</td>
        <td>
          <a href="{url_for('operador_completar_nota', nota_id=n.id)}" class="btn btn-primary" style="padding:6px 12px; font-size:12px;">✏️ Completar</a>
        </td>
      </tr>
"""
        content += """
    </tbody>
  </table>
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


@app.route("/operador/guardar_defaults", methods=["POST"])
@login_required
@role_required(OP_ROLE)
def operador_guardar_defaults():
    try:
        ok_puesto, puesto = validate_puesto(request.form.get("puesto", ""))
        if not ok_puesto:
            flash(puesto, "danger")
            return redirect(url_for("operador_home"))
        
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
        flash("Nota no encontrada.", "danger")
        return redirect(url_for("operador_home"))
    
    if nota.estado != "PENDIENTE":
        flash("Esta nota ya fue completada.", "warning")
        return redirect(url_for("operador_puesto", puesto=nota.puesto))
    
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
    
    content = f"""
<div class="panel">
  <h2>✏️ Completar Nota #{nota.id}</h2>
  <p><strong>N° Nota:</strong> {nota.nro_nota} | <strong>Autoriza:</strong> {nota.autoriza} | <strong>Puesto:</strong> {nota.puesto}</p>
</div>

<div class="panel">
  <form method="POST">
    {csrf_field()}
    <div class="grid">
      <div class="form-group">
        <label>Entrega - Nombre</label>
        <input type="text" name="entrega_nombre" value="{pre.get('entrega_nombre', '')}" required />
      </div>
      <div class="form-group">
        <label>Entrega - Legajo</label>
        <input type="text" name="entrega_legajo" value="{pre.get('entrega_legajo', '')}" required placeholder="Ej: 501123" />
      </div>
      <div class="form-group">
        <label>Recibe - Nombre</label>
        <input type="text" name="recibe_nombre" value="{pre.get('recibe_nombre', '')}" required />
      </div>
      <div class="form-group">
        <label>Recibe - Legajo</label>
        <input type="text" name="recibe_legajo" value="{pre.get('recibe_legajo', '')}" required placeholder="Ej: 502456" />
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
    <a href="{url_for('operador_puesto', puesto=nota.puesto)}" class="btn btn-secondary">← Cancelar</a>
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
    puestos = sorted(set([n.puesto for n in notas_recientes]))
    
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


# =========================
# Run
# =========================
if __name__ == "__main__":
    port = int(os.getenv("PORT", 5000))
    debug = _bool_env("FLASK_DEBUG", False)
    app.run(host="0.0.0.0", port=port, debug=debug)
