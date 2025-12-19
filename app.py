from datetime import datetime
from functools import wraps
import io
import csv

from flask import Flask, request, redirect, url_for, render_template_string, abort, send_file
from flask_sqlalchemy import SQLAlchemy
from flask_login import (
    LoginManager, login_user, logout_user,
    login_required, current_user, UserMixin
)
from werkzeug.security import generate_password_hash, check_password_hash


# =========================
# CONFIG
# =========================
app = Flask(__name__)
app.config["SECRET_KEY"] = "CAMBIAR_ESTO_POR_UNA_CLAVE_LARGA_Y_UNICA"
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///nur.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

# Cambiá este número por el tuyo (formato internacional sin +, sin espacios)
# Ejemplo CABA: 54911XXXXXXXXXX
WHATSAPP_NUMBER = "54911XXXXXXXXXX"

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = "login"


# =========================
# HELPERS
# =========================
def role_required(role_name: str):
    def deco(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            if not current_user.is_authenticated:
                return login_manager.unauthorized()
            if current_user.role != role_name:
                abort(403)
            return fn(*args, **kwargs)
        return wrapper
    return deco


def validate_legajo(legajo_raw: str):
    """
    Legajo válido: solo dígitos, rango 500000..512000
    """
    legajo = (legajo_raw or "").strip()
    if not legajo:
        return False, "Falta legajo."
    if not legajo.isdigit():
        return False, "Legajo inválido: SOLO números (sin puntos ni comas). Ej: 501123"
    val = int(legajo)
    if val < 500000 or val > 512000:
        return False, "Legajo fuera de rango (500000 a 512000). Revisá el legajo."
    return True, ""


def get_puestos_pendientes():
    rows = (
        db.session.query(Nota.puesto)
        .filter(Nota.estado == "PENDIENTE")
        .distinct()
        .order_by(Nota.puesto.asc())
        .all()
    )
    return [r[0] for r in rows]


def get_puestos_historicos():
    rows = (
        db.session.query(Nota.puesto)
        .distinct()
        .order_by(Nota.puesto.asc())
        .all()
    )
    return [r[0] for r in rows]


# =========================
# MODELOS
# =========================
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), nullable=False, default="operador")  # admin / operador

    def set_password(self, pw: str):
        self.password_hash = generate_password_hash(pw, method="pbkdf2:sha256")

    def check_password(self, pw: str):
        return check_password_hash(self.password_hash, pw)

    def __repr__(self):
        return f"<User {self.username}>"


class Nota(db.Model):
    id = db.Column(db.Integer, primary_key=True)

    nro_nota = db.Column(db.String(50), nullable=False, index=True)
    autoriza = db.Column(db.String(10), nullable=False)  # AVSEC / OPER
    puesto = db.Column(db.String(50), nullable=False, index=True)
    estado = db.Column(db.String(15), nullable=False, default="PENDIENTE")  # PENDIENTE / COMPLETADA

    entrega_nombre = db.Column(db.String(120))
    entrega_legajo = db.Column(db.String(50))
    recibe_nombre = db.Column(db.String(120))
    recibe_legajo = db.Column(db.String(50))
    fecha_hora_recepcion = db.Column(db.DateTime)
    observaciones = db.Column(db.Text)

    creado_por = db.Column(db.String(120))
    creado_en = db.Column(db.DateTime, default=datetime.utcnow)

    completado_por = db.Column(db.String(120))
    completado_en = db.Column(db.DateTime)

    __table_args__ = (
        db.UniqueConstraint("nro_nota", "puesto", name="uq_nro_puesto"),
    )


class DeliveryDefaults(db.Model):
    """
    Defaults GLOBAL por usuario (Entrega).
    """
    __tablename__ = "user_defaults"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False, unique=True)

    entrega_nombre = db.Column(db.String(120), nullable=False)
    entrega_legajo = db.Column(db.String(50), nullable=False)

    updated_at = db.Column(db.DateTime, default=datetime.utcnow)


class ReceiveDefaults(db.Model):
    """
    Defaults por usuario + puesto (Recibe).
    """
    __tablename__ = "puesto_defaults"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    puesto = db.Column(db.String(50), nullable=False, index=True)

    recibe_nombre = db.Column(db.String(120), nullable=False)
    recibe_legajo = db.Column(db.String(50), nullable=False)

    updated_at = db.Column(db.DateTime, default=datetime.utcnow)

    __table_args__ = (
        db.UniqueConstraint("user_id", "puesto", name="uq_user_puesto_defaults"),
    )


class ErrorReport(db.Model):
    __tablename__ = "error_reports"

    id = db.Column(db.Integer, primary_key=True)
    creado_por = db.Column(db.String(120), nullable=False)
    puesto = db.Column(db.String(50), nullable=False)
    nro_nota = db.Column(db.String(50), nullable=False)
    detalle = db.Column(db.Text, nullable=False)
    estado = db.Column(db.String(20), nullable=False, default="ABIERTO")  # ABIERTO / RESUELTO
    creado_en = db.Column(db.DateTime, default=datetime.utcnow)

    resuelto_por = db.Column(db.String(120))
    resuelto_en = db.Column(db.DateTime)
    comentario_admin = db.Column(db.Text)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# =========================
# UI (más prolijo, tablet-friendly)
# =========================
BASE_CSS = """
<style>
  :root{
    --bg:#f5f7fb;
    --card:#ffffff;
    --text:#111827;
    --muted:#6b7280;
    --primary:#2563eb;
    --primary2:#1d4ed8;
    --ok:#047857;
    --err:#b91c1c;
    --border:#e5e7eb;
    --shadow: 0 10px 30px rgba(17,24,39,.08);
    --radius:16px;
  }
  body{
    font-family: ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, Arial, sans-serif;
    background: var(--bg);
    color: var(--text);
    margin: 0;
    padding: 18px;
  }
  .wrap{ max-width: 980px; margin: 0 auto; }
  h2{ margin: 8px 0 14px; }
  .card{
    background: var(--card);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    padding: 16px;
    box-shadow: var(--shadow);
    margin: 12px 0;
  }
  label{ font-weight: 650; font-size: 14px; }
  input, select, textarea, button{
    font-size: 16px;
    padding: 12px;
    width: 100%;
    box-sizing: border-box;
    margin-top: 6px;
    border-radius: 12px;
    border: 1px solid var(--border);
    background: #fff;
    outline: none;
  }
  input:focus, select:focus, textarea:focus{
    border-color: rgba(37,99,235,.65);
    box-shadow: 0 0 0 4px rgba(37,99,235,.12);
  }
  button{
    cursor: pointer;
    border: none;
    background: var(--primary);
    color: white;
    font-weight: 700;
  }
  button:hover{ background: var(--primary2); }
  .btnrow{
    display:flex; gap:10px; flex-wrap:wrap;
    margin-top: 10px;
  }
  .btnrow button, .btnrow a.btn{
    width:auto; min-width: 220px;
  }
  a{ color: var(--primary); text-decoration: none; font-weight: 650; }
  a:hover{ text-decoration: underline; }
  .small{ color: var(--muted); font-size: 13px; margin-top: 8px;}
  .ok{ color: var(--ok); font-weight: 800; }
  .err{ color: var(--err); font-weight: 800; }
  .row{ display:grid; grid-template-columns: 1fr 1fr; gap: 12px; }
  hr{ border: none; border-top: 1px solid var(--border); margin: 14px 0; }
  .pill{
    display:inline-block; padding: 6px 10px; border-radius: 999px;
    background: rgba(37,99,235,.10); color: var(--primary); font-weight: 800; font-size: 12px;
  }
  .secondary{
    background: #111827;
  }
  .secondary:hover{ background: #0b1220; }
  .danger{
    background: #b91c1c;
  }
  .danger:hover{ background: #991b1b; }
  .btn{
    display:inline-flex; align-items:center; justify-content:center;
    padding: 12px 14px; border-radius: 12px;
    background: #111827; color:#fff;
  }
  .btn.whatsapp{ background: #16a34a; }
  .btn.whatsapp:hover{ background: #15803d; }
  @media (max-width: 720px){
    .row{ grid-template-columns: 1fr; }
    .btnrow button, .btnrow a.btn{ width:100%; min-width: unset; }
  }
</style>
"""


# =========================
# TEMPLATES
# =========================
LOGIN_TMPL = BASE_CSS + """
<div class="wrap">
  <h2>Login</h2>
  <div class="card">
    <form method="post">
      <label>Usuario</label>
      <input name="username" required autocomplete="username">

      <label>Contraseña</label>
      <input name="password" type="password" required autocomplete="current-password">

      <div class="btnrow">
        <button type="submit">Entrar</button>
      </div>
    </form>
    {% if msg %}<p class="err">{{msg}}</p>{% endif %}
  </div>
</div>
"""

HOME_TMPL = BASE_CSS + """
<div class="wrap">
  <h2>NUR - Panel</h2>

  <div class="card">
    <p>Usuario: <span class="pill">{{u}}</span> (rol: <span class="pill">{{r}}</span>)</p>

    <div class="card">
      <h3>Operación</h3>
      <p class="small">Podés entrar directo a un puesto con: <b>/completar?puesto=BRAVO</b> (ideal para QR).</p>
      <a href="{{url_for('completar')}}">Ir a Completar Nota</a>
    </div>

    {% if r == 'admin' %}
    <div class="card">
      <h3>Admin</h3>
      <a href="{{url_for('prefijar')}}">Prefijar Nota</a><br><br>
      <a href="{{url_for('admin_users')}}">Crear/Administrar Usuarios</a><br><br>
      <a href="{{url_for('admin_errors')}}">Ver Reportes de Error</a><br><br>
      <a href="{{url_for('export_csv')}}">Exportar CSV</a>
    </div>
    {% endif %}

    <div class="btnrow">
      <a class="btn secondary" href="{{url_for('logout')}}">Salir</a>
    </div>
  </div>
</div>
"""

PREFIJAR_TMPL = BASE_CSS + """
<div class="wrap">
  <h2>Prefijar Nota (Admin)</h2>

  <div class="card">
    <form method="post">
      <label>NroNota</label>
      <input name="nro_nota" required placeholder="Ej: 9481">

      <label>Autoriza</label>
      <select name="autoriza" required>
        <option value="AVSEC">AVSEC</option>
        <option value="OPER">OPER</option>
      </select>

      <label>Puesto</label>
      <input name="puesto" required placeholder="Ej: BRAVO / PAMPA / T3">

      <div class="btnrow">
        <button type="submit">Crear (Estado = PENDIENTE)</button>
        <a class="btn secondary" href="{{url_for('home')}}">Volver</a>
      </div>
    </form>

    {% if ok %}<p class="ok">{{ok}}</p>{% endif %}
    {% if err %}<p class="err">{{err}}</p>{% endif %}
  </div>
</div>
"""

ADMIN_USERS_TMPL = BASE_CSS + """
<div class="wrap">
  <h2>Usuarios (Admin)</h2>

  <div class="card">
    <h3>Crear usuario operador</h3>
    <form method="post">
      <input type="hidden" name="action" value="create_user">

      <label>Usuario (ej: PSA)</label>
      <input name="username" required>

      <label>Contraseña</label>
      <input name="password" type="password" required>

      <div class="btnrow">
        <button type="submit">Crear operador</button>
        <a class="btn secondary" href="{{url_for('home')}}">Volver</a>
      </div>
    </form>

    {% if ok %}<p class="ok">{{ok}}</p>{% endif %}
    {% if err %}<p class="err">{{err}}</p>{% endif %}
  </div>

  <div class="card">
    <h3>Listado</h3>
    <table border="1" cellpadding="10" cellspacing="0" style="width:100%; border-collapse:collapse; border-radius:12px; overflow:hidden;">
      <tr><th>Usuario</th><th>Rol</th></tr>
      {% for u in users %}
        <tr><td>{{u.username}}</td><td>{{u.role}}</td></tr>
      {% endfor %}
    </table>
  </div>
</div>
"""

COMPLETAR_TMPL = BASE_CSS + """
<div class="wrap">
  <h2>Completar Nota</h2>

  <div class="card">
    <form method="get">
      <label>Puesto</label>
      <select name="puesto" required>
        {% for p in puestos %}
          <option value="{{p}}" {% if p == puesto %}selected{% endif %}>{{p}}</option>
        {% endfor %}
      </select>
      <div class="btnrow">
        <button type="submit">Cargar puesto</button>
        <a class="btn secondary" href="{{url_for('home')}}">Volver</a>
      </div>
    </form>
    <p class="small">Tip: podés usar QR tipo <b>/completar?puesto=BRAVO</b> para entrar ya filtrado.</p>
  </div>

  {% if puesto %}
    <div class="card">
      <h3>Pendientes en {{puesto}}</h3>

      {% if pendientes|length == 0 %}
        <p class="err">No hay notas PENDIENTES para este puesto.</p>

        <div class="btnrow">
          <a class="btn danger" href="{{url_for('reportar_error', puesto=puesto)}}">Me equivoqué / Reportar un error</a>
        </div>
      {% else %}
        <form method="post">
          <input type="hidden" name="puesto" value="{{puesto}}">

          <label>Seleccione N° de Nota pendiente</label>
          <select name="nota_id" required>
            {% for n in pendientes %}
              <option value="{{n.id}}">
                {{n.nro_nota}} ({{n.autoriza}}) - creada {{n.creado_en.strftime('%d/%m %H:%M') if n.creado_en else ''}}
              </option>
            {% endfor %}
          </select>

          <p class="small">
            Si completaste mal algo: <a href="{{url_for('reportar_error', puesto=puesto)}}">reportalo acá</a>.
          </p>

          <hr>

          <h3>Datos de Guardia</h3>
          <p class="small">
            <b>Guardar selección</b> guarda: Entrega (global) + Recibe (por puesto).
          </p>

          <div class="row">
            <div>
              <label>Entrega - Apellido y Nombre</label>
              <input name="entrega_nombre" required value="{{entrega_nombre}}">
            </div>
            <div>
              <label>Entrega - Legajo</label>
              <input name="entrega_legajo"
                     required
                     inputmode="numeric"
                     pattern="\\d{6}"
                     placeholder="Solo números (500000 a 512000)"
                     value="{{entrega_legajo}}">
              <p class="small">Solo números, sin puntos ni comas. Ej: 501123</p>
            </div>
          </div>

          <div class="row">
            <div>
              <label>Recibe - Apellido y Nombre</label>
              <input name="recibe_nombre" required value="{{recibe_nombre}}">
            </div>
            <div>
              <label>Recibe - Legajo</label>
              <input name="recibe_legajo"
                     required
                     inputmode="numeric"
                     pattern="\\d{6}"
                     placeholder="Solo números (500000 a 512000)"
                     value="{{recibe_legajo}}">
              <p class="small">Solo números, sin puntos ni comas. Ej: 501123</p>
            </div>
          </div>

          <label>Observaciones (opcional)</label>
          <textarea name="observaciones" rows="3">{{observaciones}}</textarea>

          <div class="btnrow">
            <button type="submit" name="action" value="save_defaults">Guardar selección</button>
            <button type="submit" name="action" value="complete">Completar</button>
            <a class="btn danger" href="{{url_for('reportar_error', puesto=puesto)}}">Me equivoqué / Reportar un error</a>
          </div>
        </form>
      {% endif %}

      {% if ok %}<p class="ok">{{ok}}</p>{% endif %}
      {% if err %}<p class="err">{{err}}</p>{% endif %}
    </div>
  {% endif %}
</div>
"""

REPORT_ERROR_TMPL = BASE_CSS + """
<div class="wrap">
  <h2>Reportar un error</h2>

  <div class="card">
    <p class="small">
      Esto genera un “ticket” interno en la base de datos para que el admin lo corrija.
      Si querés, también podés avisar por WhatsApp.
    </p>

    <form method="post">
      <label>Puesto</label>
      <select name="puesto" required>
        {% for p in puestos %}
          <option value="{{p}}" {% if p == puesto %}selected{% endif %}>{{p}}</option>
        {% endfor %}
      </select>

      <label>N° de Nota</label>
      <input name="nro_nota" required placeholder="Ej: 9481" value="{{nro_nota}}">

      <label>¿Qué pasó?</label>
      <textarea name="detalle" rows="4" required placeholder="Ej: Se completó con legajo mal, hay que corregir entrega/recibe..."></textarea>

      <div class="btnrow">
        <button type="submit">Enviar reporte</button>
        <a class="btn secondary" href="{{url_for('completar', puesto=puesto)}}">Volver a completar</a>
        {% if whatsapp_url %}
          <a class="btn whatsapp" href="{{whatsapp_url}}" target="_blank" rel="noopener">Avisar por WhatsApp</a>
        {% endif %}
      </div>
    </form>

    {% if ok %}<p class="ok">{{ok}}</p>{% endif %}
    {% if err %}<p class="err">{{err}}</p>{% endif %}
  </div>
</div>
"""

ADMIN_ERRORS_TMPL = BASE_CSS + """
<div class="wrap">
  <h2>Reportes de Error (Admin)</h2>

  <div class="card">
    <p class="small">Acá ves los tickets que cargó el personal. Podés marcarlos como resueltos.</p>

    {% if ok %}<p class="ok">{{ok}}</p>{% endif %}
    {% if err %}<p class="err">{{err}}</p>{% endif %}

    <table border="1" cellpadding="10" cellspacing="0" style="width:100%; border-collapse:collapse;">
      <tr>
        <th>ID</th><th>Estado</th><th>Creado</th><th>Usuario</th><th>Puesto</th><th>Nro Nota</th><th>Detalle</th><th>Acción</th>
      </tr>
      {% for t in tickets %}
      <tr>
        <td>{{t.id}}</td>
        <td><b>{{t.estado}}</b></td>
        <td>{{t.creado_en.strftime('%d/%m %H:%M') if t.creado_en else ''}}</td>
        <td>{{t.creado_por}}</td>
        <td>{{t.puesto}}</td>
        <td>{{t.nro_nota}}</td>
        <td style="max-width:420px;">{{t.detalle}}</td>
        <td>
          {% if t.estado != 'RESUELTO' %}
            <form method="post" style="margin:0;">
              <input type="hidden" name="ticket_id" value="{{t.id}}">
              <button type="submit" name="action" value="resolve" class="secondary">Marcar resuelto</button>
            </form>
          {% else %}
            OK
          {% endif %}
        </td>
      </tr>
      {% endfor %}
    </table>

    <div class="btnrow">
      <a class="btn secondary" href="{{url_for('home')}}">Volver</a>
    </div>
  </div>
</div>
"""


# =========================
# ROUTES
# =========================
@app.route("/login", methods=["GET", "POST"])
def login():
    msg = ""
    if request.method == "POST":
        u = User.query.filter_by(username=request.form["username"].strip()).first()
        if u and u.check_password(request.form["password"]):
            login_user(u)
            next_url = request.args.get("next")
            return redirect(next_url or url_for("home"))
        msg = "Credenciales inválidas"
    return render_template_string(LOGIN_TMPL, msg=msg)


@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("login"))


@app.route("/")
@login_required
def home():
    return render_template_string(HOME_TMPL, u=current_user.username, r=current_user.role)


# --- ADMIN: Prefijar ---
@app.route("/admin/prefijar", methods=["GET", "POST"])
@login_required
@role_required("admin")
def prefijar():
    ok = ""
    err = ""
    if request.method == "POST":
        nro = request.form["nro_nota"].strip()
        aut = request.form["autoriza"].strip().upper()
        puesto = request.form["puesto"].strip().upper()

        try:
            n = Nota(
                nro_nota=nro,
                autoriza=aut,
                puesto=puesto,
                estado="PENDIENTE",
                creado_por=current_user.username
            )
            db.session.add(n)
            db.session.commit()
            ok = f"OK: Prefijada {nro} / {puesto} / {aut} (PENDIENTE)"
        except Exception:
            db.session.rollback()
            err = "Error: ya existe esa combinación NroNota + Puesto, o hubo un problema."
    return render_template_string(PREFIJAR_TMPL, ok=ok, err=err)


# --- ADMIN: Usuarios ---
@app.route("/admin/users", methods=["GET", "POST"])
@login_required
@role_required("admin")
def admin_users():
    ok = ""
    err = ""

    if request.method == "POST":
        action = request.form.get("action", "")
        if action == "create_user":
            username = request.form["username"].strip()
            password = request.form["password"]

            if User.query.filter_by(username=username).first():
                err = "Ese usuario ya existe."
            else:
                u = User(username=username, role="operador")
                u.set_password(password)
                db.session.add(u)
                db.session.commit()
                ok = f"OK: Operador creado ({username})."

    users = User.query.order_by(User.role.asc(), User.username.asc()).all()
    return render_template_string(ADMIN_USERS_TMPL, users=users, ok=ok, err=err)


# --- OPERADOR: Completar ---
@app.route("/completar", methods=["GET", "POST"])
@login_required
def completar():
    puestos = get_puestos_pendientes()

    puesto = (request.args.get("puesto") or request.form.get("puesto") or "").strip().upper()
    if not puesto and puestos:
        puesto = puestos[0]

    ok = ""
    err = ""
    observaciones = ""

    # Defaults entrega (global)
    entrega_nombre = ""
    entrega_legajo = ""
    d_ent = DeliveryDefaults.query.filter_by(user_id=current_user.id).first()
    if d_ent:
        entrega_nombre = d_ent.entrega_nombre
        entrega_legajo = d_ent.entrega_legajo

    # Defaults recibe (por puesto)
    recibe_nombre = ""
    recibe_legajo = ""
    d_rec = None
    if puesto:
        d_rec = ReceiveDefaults.query.filter_by(user_id=current_user.id, puesto=puesto).first()
        if d_rec:
            recibe_nombre = d_rec.recibe_nombre
            recibe_legajo = d_rec.recibe_legajo

    pendientes = []
    if puesto:
        pendientes = (
            Nota.query
            .filter_by(puesto=puesto, estado="PENDIENTE")
            .order_by(Nota.creado_en.asc())
            .all()
        )

    if request.method == "POST":
        action = request.form.get("action", "complete")
        observaciones = (request.form.get("observaciones") or "").strip()

        entrega_nombre_in = request.form.get("entrega_nombre", "").strip()
        entrega_legajo_in = request.form.get("entrega_legajo", "").strip()
        recibe_nombre_in = request.form.get("recibe_nombre", "").strip()
        recibe_legajo_in = request.form.get("recibe_legajo", "").strip()

        # Validaciones legajo
        ok_leg1, msg1 = validate_legajo(entrega_legajo_in)
        ok_leg2, msg2 = validate_legajo(recibe_legajo_in)

        if action == "save_defaults":
            if not (entrega_nombre_in and entrega_legajo_in and recibe_nombre_in and recibe_legajo_in):
                err = "Para guardar selección tenés que completar Entrega/Recibe (nombre y legajo)."
            elif not ok_leg1:
                err = f"Entrega: {msg1}"
            elif not ok_leg2:
                err = f"Recibe: {msg2}"
            else:
                # Guarda ENTREGA global
                if not d_ent:
                    d_ent = DeliveryDefaults(
                        user_id=current_user.id,
                        entrega_nombre=entrega_nombre_in,
                        entrega_legajo=entrega_legajo_in
                    )
                    db.session.add(d_ent)
                else:
                    d_ent.entrega_nombre = entrega_nombre_in
                    d_ent.entrega_legajo = entrega_legajo_in
                    d_ent.updated_at = datetime.utcnow()

                # Guarda RECIBE por puesto
                if not puesto:
                    err = "Elegí un puesto primero."
                else:
                    if not d_rec:
                        d_rec = ReceiveDefaults(
                            user_id=current_user.id,
                            puesto=puesto,
                            recibe_nombre=recibe_nombre_in,
                            recibe_legajo=recibe_legajo_in
                        )
                        db.session.add(d_rec)
                    else:
                        d_rec.recibe_nombre = recibe_nombre_in
                        d_rec.recibe_legajo = recibe_legajo_in
                        d_rec.updated_at = datetime.utcnow()

                    db.session.commit()
                    ok = "OK: Selección guardada (Entrega global + Recibe por puesto)."

                    entrega_nombre = entrega_nombre_in
                    entrega_legajo = entrega_legajo_in
                    recibe_nombre = recibe_nombre_in
                    recibe_legajo = recibe_legajo_in

        elif action == "complete":
            nota_id = request.form.get("nota_id")
            if not nota_id:
                err = "Tenés que seleccionar una nota."
            elif not (entrega_nombre_in and entrega_legajo_in and recibe_nombre_in and recibe_legajo_in):
                err = "Completá Entrega/Recibe (nombre y legajo)."
            elif not ok_leg1:
                err = f"Entrega: {msg1}"
            elif not ok_leg2:
                err = f"Recibe: {msg2}"
            else:
                nota = Nota.query.filter_by(id=int(nota_id), puesto=puesto, estado="PENDIENTE").first()
                if not nota:
                    err = "Esa nota no está disponible como PENDIENTE para este puesto. Actualizá la página."
                else:
                    nota.entrega_nombre = entrega_nombre_in
                    nota.entrega_legajo = entrega_legajo_in
                    nota.recibe_nombre = recibe_nombre_in
                    nota.recibe_legajo = recibe_legajo_in
                    nota.observaciones = observaciones

                    nota.fecha_hora_recepcion = datetime.utcnow()
                    nota.completado_por = current_user.username
                    nota.completado_en = datetime.utcnow()
                    nota.estado = "COMPLETADA"
                    db.session.commit()

                    ok = f"OK: Completada {nota.nro_nota} / {puesto}. (Autoriza prefijado: {nota.autoriza})"

                    # Mantener para seguir rápido
                    entrega_nombre = entrega_nombre_in
                    entrega_legajo = entrega_legajo_in
                    recibe_nombre = recibe_nombre_in
                    recibe_legajo = recibe_legajo_in
                    observaciones = ""

        # recargar
        puestos = get_puestos_pendientes()
        pendientes = (
            Nota.query
            .filter_by(puesto=puesto, estado="PENDIENTE")
            .order_by(Nota.creado_en.asc())
            .all()
        )

    if not puestos:
        puestos = [puesto] if puesto else []

    return render_template_string(
        COMPLETAR_TMPL,
        puestos=puestos,
        puesto=puesto,
        pendientes=pendientes,
        ok=ok,
        err=err,
        entrega_nombre=entrega_nombre,
        entrega_legajo=entrega_legajo,
        recibe_nombre=recibe_nombre,
        recibe_legajo=recibe_legajo,
        observaciones=observaciones
    )


# --- OPERADOR: Reportar error ---
@app.route("/reportar", methods=["GET", "POST"])
@login_required
def reportar_error():
    ok = ""
    err = ""
    puestos = get_puestos_historicos()
    puesto = (request.args.get("puesto") or request.form.get("puesto") or "").strip().upper()
    nro_nota = (request.args.get("nro_nota") or request.form.get("nro_nota") or "").strip()

    if not puestos:
        # fallback
        if puesto:
            puestos = [puesto]
        else:
            puestos = ["BRAVO", "PAMPA", "T3", "INTERNACIONAL"]

    whatsapp_url = None
    if WHATSAPP_NUMBER and "X" not in WHATSAPP_NUMBER:
        text = f"NUR: Reporte de error. Puesto {puesto or '-'} / Nota {nro_nota or '-'}."
        whatsapp_url = f"https://wa.me/{WHATSAPP_NUMBER}?text={text.replace(' ', '%20')}"

    if request.method == "POST":
        detalle = (request.form.get("detalle") or "").strip()
        puesto_in = (request.form.get("puesto") or "").strip().upper()
        nro_in = (request.form.get("nro_nota") or "").strip()

        if not (puesto_in and nro_in and detalle):
            err = "Completá Puesto, N° de Nota y Detalle."
        else:
            t = ErrorReport(
                creado_por=current_user.username,
                puesto=puesto_in,
                nro_nota=nro_in,
                detalle=detalle,
                estado="ABIERTO"
            )
            db.session.add(t)
            db.session.commit()
            ok = f"OK: Reporte enviado (Ticket #{t.id})."
            # mantener puesto/nro para volver
            puesto = puesto_in
            nro_nota = nro_in

    return render_template_string(
        REPORT_ERROR_TMPL,
        ok=ok,
        err=err,
        puestos=puestos,
        puesto=puesto,
        nro_nota=nro_nota,
        whatsapp_url=whatsapp_url
    )


# --- ADMIN: Ver tickets ---
@app.route("/admin/errores", methods=["GET", "POST"])
@login_required
@role_required("admin")
def admin_errors():
    ok = ""
    err = ""

    if request.method == "POST":
        action = request.form.get("action")
        if action == "resolve":
            tid = request.form.get("ticket_id")
            t = ErrorReport.query.get(int(tid)) if tid and tid.isdigit() else None
            if not t:
                err = "Ticket no encontrado."
            else:
                t.estado = "RESUELTO"
                t.resuelto_por = current_user.username
                t.resuelto_en = datetime.utcnow()
                db.session.commit()
                ok = f"OK: Ticket #{t.id} marcado como resuelto."

    tickets = ErrorReport.query.order_by(ErrorReport.estado.asc(), ErrorReport.id.desc()).all()
    return render_template_string(ADMIN_ERRORS_TMPL, tickets=tickets, ok=ok, err=err)


# --- ADMIN: Export CSV ---
@app.route("/admin/export.csv")
@login_required
@role_required("admin")
def export_csv():
    output = io.StringIO()
    w = csv.writer(output)
    w.writerow([
        "nro_nota", "autoriza", "puesto", "estado",
        "entrega_nombre", "entrega_legajo",
        "recibe_nombre", "recibe_legajo",
        "fecha_hora_recepcion_utc",
        "observaciones",
        "creado_por", "creado_en_utc",
        "completado_por", "completado_en_utc"
    ])

    for n in Nota.query.order_by(Nota.id.desc()).all():
        w.writerow([
            n.nro_nota, n.autoriza, n.puesto, n.estado,
            n.entrega_nombre or "", n.entrega_legajo or "",
            n.recibe_nombre or "", n.recibe_legajo or "",
            n.fecha_hora_recepcion.isoformat() if n.fecha_hora_recepcion else "",
            (n.observaciones or "").replace("\n", " "),
            n.creado_por or "", n.creado_en.isoformat() if n.creado_en else "",
            n.completado_por or "", n.completado_en.isoformat() if n.completado_en else ""
        ])

    mem = io.BytesIO()
    mem.write(output.getvalue().encode("utf-8-sig"))
    mem.seek(0)
    return send_file(mem, mimetype="text/csv", as_attachment=True, download_name="nur_export.csv")


# --- CLI initdb ---
@app.cli.command("initdb")
def initdb():
    db.create_all()

    if not User.query.filter_by(username="admin").first():
        u = User(username="admin", role="admin")
        u.set_password("CambiarEstaClaveYA")
        db.session.add(u)
        db.session.commit()
        print("Creado usuario admin / password = CambiarEstaClaveYA")

    if not User.query.filter_by(username="PSA").first():
        o = User(username="PSA", role="operador")
        o.set_password("123*")
        db.session.add(o)
        db.session.commit()
        print("Creado usuario operador PSA / password = 123*")


if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(host="127.0.0.1", port=5000, debug=True)
