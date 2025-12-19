import os
import re
from datetime import datetime
from functools import wraps

from flask import (
    Flask, request, redirect, url_for, render_template_string,
    flash, session, abort
)
from flask_sqlalchemy import SQLAlchemy
from flask_login import (
    LoginManager, UserMixin, login_user, login_required,
    logout_user, current_user
)
from werkzeug.security import generate_password_hash, check_password_hash

# ---------------- CONFIG ----------------
app = Flask(__name__)

# Usá variable de entorno en Railway (Variables -> SECRET_KEY)
app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", "CAMBIAR_ESTO_POR_UNA_CLAVE_LARGA_Y_UNICA")

# SQLite local (para pruebas). En producción conviene Postgres, pero esto sirve.
# Railway suele permitir escribir en el FS del contenedor, aunque no garantiza persistencia.
app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv("DATABASE_URL", "sqlite:///nur.db")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = "login"


# ---------------- HELPERS ----------------
def role_required(*roles):
    def deco(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            if not current_user.is_authenticated:
                return redirect(url_for("login"))
            if current_user.role not in roles:
                abort(403)
            return fn(*args, **kwargs)
        return wrapper
    return deco


def normalize_legajo(raw: str) -> str:
    """Devuelve solo dígitos o ''."""
    if raw is None:
        return ""
    raw = raw.strip()
    return raw


def validate_legajo(raw: str) -> tuple[bool, str]:
    """
    Reglas:
    - Solo números (sin puntos ni comas)
    - Rango 500000 a 512000 inclusive
    """
    raw = (raw or "").strip()

    if raw == "":
        return False, "El legajo es obligatorio."

    if not raw.isdigit():
        return False, "Error: legajo inválido. Usá SOLO números, sin puntos ni comas (ej: 501123)."

    n = int(raw)
    if n < 500000 or n > 512000:
        return False, "Error: legajo fuera de rango (500000 a 512000). Revisá el legajo."
    return True, ""


def get_whatsapp_link() -> str:
    num = os.getenv("WHATSAPP_NUMBER", "").strip()
    if not num:
        return ""
    # link simple a whatsapp
    return f"https://wa.me/{num}"


# ---------------- MODELOS ----------------
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), nullable=False, default="operador")  # admin / operador

    def set_password(self, pw: str):
        self.password_hash = generate_password_hash(pw, method="pbkdf2:sha256")

    def check_password(self, pw: str) -> bool:
        return check_password_hash(self.password_hash, pw)


class Nota(db.Model):
    id = db.Column(db.Integer, primary_key=True)

    # Prefijado por ADMIN
    nro_nota = db.Column(db.String(50), nullable=False, index=True)
    autoriza = db.Column(db.String(10), nullable=False)  # AVSEC / OPER
    puesto = db.Column(db.String(60), nullable=False, index=True)
    estado = db.Column(db.String(15), nullable=False, default="PENDIENTE")  # PENDIENTE / COMPLETADA

    # Completa OPERADOR
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


class ReporteError(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nro_nota = db.Column(db.String(50), nullable=True, index=True)
    puesto = db.Column(db.String(60), nullable=True, index=True)
    detalle = db.Column(db.Text, nullable=False)
    reportado_por = db.Column(db.String(120), nullable=False)
    reportado_en = db.Column(db.DateTime, default=datetime.utcnow)


# ---------------- INIT DB (clave para Railway) ----------------
def init_db_and_seed():
    """
    Esto corre al IMPORTAR el módulo (cuando gunicorn levanta),
    así no queda sin tablas en Railway.
    """
    db.create_all()

    admin_user = os.getenv("ADMIN_USER", "admin")
    admin_pass = os.getenv("ADMIN_PASSWORD", "CambiarEstaClaveYA")

    op_user = os.getenv("OP_USER", "PSA")
    op_pass = os.getenv("OP_PASSWORD", "123*")

    if not User.query.filter_by(username=admin_user).first():
        u = User(username=admin_user, role="admin")
        u.set_password(admin_pass)
        db.session.add(u)

    if not User.query.filter_by(username=op_user).first():
        o = User(username=op_user, role="operador")
        o.set_password(op_pass)
        db.session.add(o)

    db.session.commit()


with app.app_context():
    init_db_and_seed()


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# ---------------- UI (simple pero menos rústico) ----------------
BASE_CSS = """
<style>
  :root { --bg:#0b1220; --card:#0f1b33; --text:#e9eefc; --muted:#a8b3d6; --accent:#3b82f6; --danger:#ef4444; --ok:#22c55e; }
  body { font-family: system-ui, -apple-system, Segoe UI, Roboto, Arial; background: linear-gradient(120deg, #0b1220, #111a2e); color: var(--text); margin:0; }
  .wrap { max-width: 980px; margin: 0 auto; padding: 22px; }
  .card { background: rgba(15,27,51,.92); border: 1px solid rgba(255,255,255,.08); border-radius: 16px; padding: 16px; box-shadow: 0 10px 30px rgba(0,0,0,.25); }
  h1,h2 { margin: 0 0 12px 0; }
  .row { display:flex; gap:12px; flex-wrap:wrap; }
  .row > * { flex: 1; min-width: 220px; }
  label { display:block; font-weight: 600; margin: 10px 0 6px; color: var(--muted); }
  input, select, textarea { width:100%; padding: 10px 12px; border-radius: 12px; border: 1px solid rgba(255,255,255,.12); background: rgba(255,255,255,.04); color: var(--text); outline:none; }
  textarea { min-height: 90px; }
  .btn { display:inline-block; padding: 10px 14px; border-radius: 12px; border: 1px solid rgba(255,255,255,.14); background: rgba(59,130,246,.9); color: #fff; text-decoration:none; cursor:pointer; font-weight:700; }
  .btn.secondary { background: rgba(255,255,255,.08); }
  .btn.danger { background: rgba(239,68,68,.9); }
  .pill { display:inline-block; padding: 3px 10px; border-radius: 999px; font-size: 12px; background: rgba(255,255,255,.08); color: var(--muted); }
  .msg { margin: 10px 0; padding: 10px 12px; border-radius: 12px; border: 1px solid rgba(255,255,255,.12); background: rgba(255,255,255,.06); }
  .msg.err { border-color: rgba(239,68,68,.6); color: #ffd1d1; }
  .msg.ok { border-color: rgba(34,197,94,.6); color: #c8ffdc; }
  table { width:100%; border-collapse: collapse; margin-top: 10px; }
  th, td { text-align:left; padding: 10px; border-bottom: 1px solid rgba(255,255,255,.08); }
  th { color: var(--muted); font-size: 12px; letter-spacing: .04em; text-transform: uppercase; }
  .topbar { display:flex; justify-content: space-between; align-items:center; margin-bottom: 14px; gap: 12px; flex-wrap: wrap; }
  .link { color: #9cc4ff; text-decoration: none; }
</style>
"""


LOGIN_TMPL = BASE_CSS + """
<div class="wrap">
  <div class="card" style="max-width:520px;margin:0 auto;">
    <h1>Login</h1>
    {% if msg %}<div class="msg err">{{msg}}</div>{% endif %}
    <form method="post">
      <label>Usuario</label>
      <input name="username" required>
      <label>Contraseña</label>
      <input name="password" type="password" required>
      <div style="margin-top:14px;">
        <button class="btn" type="submit">Entrar</button>
      </div>
    </form>
  </div>
</div>
"""


HOME_TMPL = BASE_CSS + """
<div class="wrap">
  <div class="topbar">
    <div>
      <h1>NUR</h1>
      <div class="pill">Usuario: {{u}} • Rol: {{r}}</div>
    </div>
    <div>
      <a class="btn secondary" href="{{url_for('logout')}}">Salir</a>
    </div>
  </div>

  <div class="card">
    {% if r == 'admin' %}
      <h2>Panel Admin</h2>
      <p style="color:var(--muted);margin-top:6px;">Prefijá números de nota y puesto. El operador solo completa.</p>
      <a class="btn" href="{{url_for('prefijar')}}">Prefijar notas</a>
      <a class="btn secondary" href="{{url_for('admin_listado')}}">Ver/Buscar</a>
    {% else %}
      <h2>Modo Operador</h2>
      <p style="color:var(--muted);margin-top:6px;">Elegí un puesto y completá las pendientes.</p>
      <a class="btn" href="{{url_for('operador')}}">Ir a Operador</a>
    {% endif %}
  </div>
</div>
"""


PUESTOS_DEFAULT = ["PAMPA", "NACIONAL T3", "INTERNACIONAL", "BRAVO", "PROVEEDORES", "CARGAS"]


PREFIJAR_TMPL = BASE_CSS + """
<div class="wrap">
  <div class="topbar">
    <h1>Prefijar notas</h1>
    <a class="btn secondary" href="{{url_for('home')}}">Volver</a>
  </div>

  <div class="card">
    {% if ok %}<div class="msg ok">{{ok}}</div>{% endif %}
    {% if err %}<div class="msg err">{{err}}</div>{% endif %}

    <form method="post">
      <div class="row">
        <div>
          <label>Autoriza</label>
          <select name="autoriza" required>
            <option value="AVSEC">AVSEC</option>
            <option value="OPER">OPER</option>
          </select>
        </div>
        <div>
          <label>Puesto</label>
          <select name="puesto" required>
            {% for p in puestos %}
              <option value="{{p}}">{{p}}</option>
            {% endfor %}
          </select>
        </div>
      </div>

      <label>Números de nota (uno por línea)</label>
      <textarea name="nros" placeholder="Ej:\n9481\n9517\n9513" required></textarea>

      <div style="margin-top:12px;">
        <button class="btn" type="submit">Crear pendientes</button>
      </div>
    </form>
  </div>
</div>
"""


OPERADOR_TMPL = BASE_CSS + """
<div class="wrap">
  <div class="topbar">
    <h1>Operador</h1>
    <a class="btn secondary" href="{{url_for('home')}}">Volver</a>
  </div>

  <div class="card">
    <form method="get">
      <div class="row">
        <div>
          <label>Puesto</label>
          <select name="puesto" required>
            <option value="">-- Elegir --</option>
            {% for p in puestos %}
              <option value="{{p}}" {% if p==puesto %}selected{% endif %}>{{p}}</option>
            {% endfor %}
          </select>
        </div>
        <div style="align-self:end;">
          <button class="btn" type="submit">Cargar pendientes</button>
        </div>
      </div>
    </form>

    <hr style="border:0;border-top:1px solid rgba(255,255,255,.08);margin:14px 0;">

    <div class="row">
      <div>
        <h2 style="margin-bottom:6px;">Pendientes{% if puesto %} • {{puesto}}{% endif %}</h2>
        <div style="color:var(--muted);">
          Tip: podés guardar “Selección” para acelerar carga (se guarda por puesto).
        </div>
      </div>
      <div style="text-align:right;">
        <a class="btn secondary" href="{{url_for('reportar_error')}}">Completo mal una planilla, toque aquí</a>
        {% if wsp %}
          <a class="btn secondary" target="_blank" href="{{wsp}}">WhatsApp</a>
        {% endif %}
      </div>
    </div>

    {% if not puesto %}
      <div class="msg">Elegí un puesto para ver pendientes.</div>
    {% else %}
      {% if notas|length == 0 %}
        <div class="msg">No hay pendientes para este puesto.</div>
      {% else %}
        <table>
          <thead>
            <tr>
              <th>Nro Nota</th>
              <th>Autoriza</th>
              <th>Estado</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {% for n in notas %}
              <tr>
                <td>{{n.nro_nota}}</td>
                <td>{{n.autoriza}}</td>
                <td>{{n.estado}}</td>
                <td style="text-align:right;">
                  <a class="btn" href="{{url_for('completar_nota', nota_id=n.id)}}">Completar</a>
                </td>
              </tr>
            {% endfor %}
          </tbody>
        </table>
      {% endif %}
    {% endif %}
  </div>
</div>
"""


COMPLETAR_TMPL = BASE_CSS + """
<div class="wrap">
  <div class="topbar">
    <h1>Completar nota</h1>
    <a class="btn secondary" href="{{url_for('operador', puesto=nota.puesto)}}">Volver</a>
  </div>

  <div class="card">
    {% if err %}<div class="msg err">{{err}}</div>{% endif %}
    {% if ok %}<div class="msg ok">{{ok}}</div>{% endif %}

    <div class="row">
      <div>
        <label>Puesto</label>
        <input value="{{nota.puesto}}" readonly>
      </div>
      <div>
        <label>Nro Nota</label>
        <input value="{{nota.nro_nota}}" readonly>
      </div>
      <div>
        <label>Autoriza</label>
        <input value="{{nota.autoriza}}" readonly>
      </div>
    </div>

    <form method="post" style="margin-top:8px;">
      <h2 style="margin-top:10px;">Entrega</h2>
      <div class="row">
        <div>
          <label>Apellido y Nombre</label>
          <input name="entrega_nombre" value="{{pref.entrega_nombre}}" required>
        </div>
        <div>
          <label>Legajo (500000–512000)</label>
          <input name="entrega_legajo" inputmode="numeric" placeholder="Ej: 501123" value="{{pref.entrega_legajo}}" required>
        </div>
      </div>

      <h2 style="margin-top:10px;">Recibe</h2>
      <div class="row">
        <div>
          <label>Apellido y Nombre</label>
          <input name="recibe_nombre" value="{{pref.recibe_nombre}}" required>
        </div>
        <div>
          <label>Legajo (500000–512000)</label>
          <input name="recibe_legajo" inputmode="numeric" placeholder="Ej: 501123" value="{{pref.recibe_legajo}}" required>
        </div>
      </div>

      <label>Observaciones (opcional)</label>
      <textarea name="observaciones">{{pref.observaciones}}</textarea>

      <div class="row" style="align-items:center;">
        <div>
          <label style="margin-bottom:0;">
            <input type="checkbox" name="guardar_seleccion" value="1" checked>
            Guardar selección para este puesto (Entrega y Recibe)
          </label>
          <div style="color:var(--muted);font-size:12px;">
            Se guarda por puesto. Si cambiás de puesto, mantiene defaults distintos.
          </div>
        </div>
        <div style="text-align:right;align-self:end;">
          <button class="btn" type="submit">Confirmar completada</button>
        </div>
      </div>
    </form>
  </div>
</div>
"""


REPORTAR_ERROR_TMPL = BASE_CSS + """
<div class="wrap">
  <div class="topbar">
    <h1>Reportar error</h1>
    <a class="btn secondary" href="{{url_for('operador')}}">Volver</a>
  </div>

  <div class="card">
    {% if ok %}<div class="msg ok">{{ok}}</div>{% endif %}
    {% if err %}<div class="msg err">{{err}}</div>{% endif %}

    <form method="post">
      <div class="row">
        <div>
          <label>Puesto (opcional)</label>
          <select name="puesto">
            <option value="">--</option>
            {% for p in puestos %}
              <option value="{{p}}">{{p}}</option>
            {% endfor %}
          </select>
        </div>
        <div>
          <label>Nro Nota (opcional)</label>
          <input name="nro_nota" placeholder="Ej: 9481">
        </div>
      </div>

      <label>Detalle del error</label>
      <textarea name="detalle" placeholder="Contá qué pasó y qué habría que corregir" required></textarea>

      <div style="margin-top:12px;">
        <button class="btn" type="submit">Enviar reporte</button>
      </div>
    </form>
  </div>
</div>
"""


ADMIN_LISTADO_TMPL = BASE_CSS + """
<div class="wrap">
  <div class="topbar">
    <h1>Admin • Listado</h1>
    <a class="btn secondary" href="{{url_for('home')}}">Volver</a>
  </div>

  <div class="card">
    <form method="get">
      <div class="row">
        <div>
          <label>Buscar por Nro Nota</label>
          <input name="q" value="{{q}}" placeholder="Ej: 9481">
        </div>
        <div>
          <label>Estado</label>
          <select name="estado">
            <option value="">--</option>
            <option value="PENDIENTE" {% if estado=='PENDIENTE' %}selected{% endif %}>PENDIENTE</option>
            <option value="COMPLETADA" {% if estado=='COMPLETADA' %}selected{% endif %}>COMPLETADA</option>
          </select>
        </div>
        <div style="align-self:end;">
          <button class="btn" type="submit">Filtrar</button>
        </div>
      </div>
    </form>

    <table>
      <thead>
        <tr>
          <th>Nro Nota</th><th>Puesto</th><th>Autoriza</th><th>Estado</th><th>Recibido</th>
        </tr>
      </thead>
      <tbody>
        {% for n in notas %}
        <tr>
          <td>{{n.nro_nota}}</td>
          <td>{{n.puesto}}</td>
          <td>{{n.autoriza}}</td>
          <td>{{n.estado}}</td>
          <td>
            {% if n.fecha_hora_recepcion %}
              {{n.fecha_hora_recepcion}}
            {% else %}
              -
            {% endif %}
          </td>
        </tr>
        {% endfor %}
      </tbody>
    </table>
  </div>
</div>
"""


# ---------------- ROUTES ----------------
@app.route("/login", methods=["GET", "POST"])
def login():
    msg = ""
    if request.method == "POST":
        try:
            username = request.form.get("username", "").strip()
            password = request.form.get("password", "")

            u = User.query.filter_by(username=username).first()
            if u and u.check_password(password):
                login_user(u)
                return redirect(url_for("home"))
            msg = "Credenciales inválidas"
        except Exception:
            # No exponemos detalles al usuario
            msg = "Error interno al intentar ingresar. Revisá el servicio o avisá al administrador."
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
        autoriza = request.form.get("autoriza", "").strip()
        puesto = request.form.get("puesto", "").strip()
        nros = request.form.get("nros", "")

        if autoriza not in ["AVSEC", "OPER"]:
            err = "Autoriza inválido."
        elif not puesto:
            err = "Puesto inválido."
        else:
            lines = [ln.strip() for ln in nros.splitlines() if ln.strip()]
            if not lines:
                err = "Pegá al menos un número de nota."
            else:
                creadas = 0
                for nro in lines:
                    db.session.add(Nota(
                        nro_nota=nro,
                        autoriza=autoriza,
                        puesto=puesto,
                        estado="PENDIENTE",
                        creado_por=current_user.username
                    ))
                    creadas += 1
                db.session.commit()
                ok = f"Listo. Se crearon {creadas} pendientes para {puesto}."

    return render_template_string(PREFIJAR_TMPL, ok=ok, err=err, puestos=PUESTOS_DEFAULT)


@app.route("/admin/listado")
@login_required
@role_required("admin")
def admin_listado():
    q = (request.args.get("q") or "").strip()
    estado = (request.args.get("estado") or "").strip()

    query = Nota.query
    if q:
        query = query.filter(Nota.nro_nota.contains(q))
    if estado in ["PENDIENTE", "COMPLETADA"]:
        query = query.filter_by(estado=estado)

    notas = query.order_by(Nota.creado_en.desc()).limit(300).all()
    return render_template_string(ADMIN_LISTADO_TMPL, notas=notas, q=q, estado=estado)


# --- OPERADOR ---
@app.route("/operador")
@login_required
@role_required("operador", "admin")  # si querés que admin también pueda completar
def operador():
    puesto = (request.args.get("puesto") or "").strip()
    notas = []
    if puesto:
        notas = Nota.query.filter_by(puesto=puesto, estado="PENDIENTE").order_by(Nota.id.asc()).all()
    return render_template_string(
        OPERADOR_TMPL,
        puesto=puesto,
        notas=notas,
        puestos=PUESTOS_DEFAULT,
        wsp=get_whatsapp_link()
    )


def get_defaults_for_puesto(puesto: str) -> dict:
    data = session.get("defaults_por_puesto", {})
    return data.get(puesto, {
        "entrega_nombre": "",
        "entrega_legajo": "",
        "recibe_nombre": "",
        "recibe_legajo": "",
        "observaciones": ""
    })


def save_defaults_for_puesto(puesto: str, payload: dict):
    data = session.get("defaults_por_puesto", {})
    data[puesto] = payload
    session["defaults_por_puesto"] = data


@app.route("/operador/completar/<int:nota_id>", methods=["GET", "POST"])
@login_required
@role_required("operador", "admin")
def completar_nota(nota_id: int):
    nota = Nota.query.get_or_404(nota_id)

    if nota.estado != "PENDIENTE":
        return redirect(url_for("operador", puesto=nota.puesto))

    err = ""
    ok = ""

    pref = get_defaults_for_puesto(nota.puesto)

    if request.method == "POST":
        entrega_nombre = (request.form.get("entrega_nombre") or "").strip()
        entrega_legajo = (request.form.get("entrega_legajo") or "").strip()
        recibe_nombre = (request.form.get("recibe_nombre") or "").strip()
        recibe_legajo = (request.form.get("recibe_legajo") or "").strip()
        observaciones = (request.form.get("observaciones") or "").strip()
        guardar = request.form.get("guardar_seleccion") == "1"

        if not entrega_nombre or not recibe_nombre:
            err = "Completá nombre de entrega y nombre de recibe."
        else:
            ok_leg_e, msg_e = validate_legajo(entrega_legajo)
            ok_leg_r, msg_r = validate_legajo(recibe_legajo)
            if not ok_leg_e:
                err = msg_e
            elif not ok_leg_r:
                err = msg_r
            else:
                # guardar defaults por puesto
                if guardar:
                    save_defaults_for_puesto(nota.puesto, {
                        "entrega_nombre": entrega_nombre,
                        "entrega_legajo": entrega_legajo,
                        "recibe_nombre": recibe_nombre,
                        "recibe_legajo": recibe_legajo,
                        "observaciones": ""
                    })

                nota.entrega_nombre = entrega_nombre
                nota.entrega_legajo = entrega_legajo
                nota.recibe_nombre = recibe_nombre
                nota.recibe_legajo = recibe_legajo
                nota.observaciones = observaciones
                nota.fecha_hora_recepcion = datetime.utcnow()
                nota.estado = "COMPLETADA"
                nota.completado_por = current_user.username
                nota.completado_en = datetime.utcnow()

                db.session.commit()
                return redirect(url_for("operador", puesto=nota.puesto))

    return render_template_string(COMPLETAR_TMPL, nota=nota, err=err, ok=ok, pref=pref)


@app.route("/reportar-error", methods=["GET", "POST"])
@login_required
@role_required("operador", "admin")
def reportar_error():
    ok = ""
    err = ""

    if request.method == "POST":
        puesto = (request.form.get("puesto") or "").strip() or None
        nro_nota = (request.form.get("nro_nota") or "").strip() or None
        detalle = (request.form.get("detalle") or "").strip()

        if not detalle:
            err = "Escribí el detalle del error."
        else:
            db.session.add(ReporteError(
                puesto=puesto,
                nro_nota=nro_nota,
                detalle=detalle,
                reportado_por=current_user.username
            ))
            db.session.commit()
            ok = "Reporte enviado. Gracias."

    return render_template_string(REPORTAR_ERROR_TMPL, ok=ok, err=err, puestos=PUESTOS_DEFAULT)


# --------------- Local run ---------------
if __name__ == "__main__":
    # Local solamente. En Railway se usa gunicorn.
    app.run(host="127.0.0.1", port=5000, debug=True)
