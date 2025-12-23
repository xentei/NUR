
## Local
```powershell
python -m venv venv
.\env\Scripts\activate
$env:SECRET_KEY="definí-una-clave-segura"
$env:ADMIN_USER="admin"
$env:ADMIN_PASS="cambiame"
$env:OP_USER="PSA"
$env:OP_PASS="cambiame"
Usuarios iniciales: si la DB está vacía se crearán al iniciar. Si faltan variables, se generan usuarios y contraseñas efímeras (solo para esa ejecución) y se muestran en la consola. Si no definís SECRET_KEY, la app genera una y la guarda en `instance/secret_key.txt` (o en el volumen `/data` en Railway) para que no falle el arranque y se mantenga entre reinicios locales. Si no seteás credenciales, el admin por defecto será `admin` con contraseña aleatoria (impresa en consola al arrancar).

## Roles disponibles
- **admin**: control total (notas, usuarios, reportes de error).
- **dop**: alta y consulta de notas; no borra usuarios.
- **operador**: completa notas y reporta errores. Podés tildar “Guardar datos de entrega y recepción” dentro de cada nota para reusar esos datos durante toda la sesión.
- **visor**: solo lectura de notas (filtros incluidos, sin acciones).

### Flujo de reseteo de contraseñas
- El admin puede resetear contraseñas desde **Admin → Usuarios**. Al hacerlo, se genera una contraseña temporal y el usuario queda marcado como "debe cambiarla".
- Cuando el usuario ingresa con la contraseña temporal, se lo redirige obligatoriamente a **/change-password** para que la reemplace (mínimo 10 caracteres). Hasta que lo haga, no podrá navegar por el resto de la app.
- La creación de usuarios no exige cambio inicial; solo los reseteos fuerzan el cambio.

### Puestos preestablecidos
Al cargar notas, elegí el puesto desde el desplegable (con búsqueda) para evitar variantes. La lista incluye, entre otros:
- ADICIONAL OTV, ADICIONAL TCA, BARRERA CARGAS, CABECERA NORTE/SUR, CHECKPOINT, GATE GOURMET, PAMPA, BRAVO, ECO, CARGAS, PREEMBARQUE INTERNACIONAL/NACIONAL, TORRE DE CONTROL.
- También podés elegir **Otro** y escribir manualmente si es un puesto nuevo puntual.
Variables recomendadas (definilas en producción; en local se generan claves/usuarios efímeras si faltan):
- SECRET_KEY
- DATABASE_URL (opcional; si falta o el driver no está disponible se usa SQLite persistente en `/data/nur.db`)

Variables opcionales:
- SQLITE_BUSY_TIMEOUT_MS (solo SQLite; default 5000)

### Durabilidad de base de datos (SQLite + volumen persistente)
- **Ruta**: si no hay `DATABASE_URL` (o si apunta a PostgreSQL pero falta `psycopg2`), la app usa `/data/nur.db` en Railway (o `instance/nur.db` en local) y mantiene ese archivo entre reinicios mientras el volumen persista.
- **PRAGMAs aplicados en cada conexión**: `journal_mode=WAL`, `synchronous=FULL`, `foreign_keys=ON`, `busy_timeout=SQLITE_BUSY_TIMEOUT_MS` (default 5000 ms).
- **Backup automático al iniciar**: si el `.db` existe, se genera `/data/backups/nur-YYYYMMDDHHMMSS.db.bak` (o `instance/backups/...`). Se loguea “Backup creado en …” o el motivo del fallo pero **no** se detiene el arranque.
- **Respaldos programados**:
  - CSV: `python app.py --export-csv --out-dir /data/backups` (genera `notas-*.csv` y `errores-*.csv` sin levantar el server). En Railway podés agendar un Job/cron con este comando.
  - Copia binaria: `cp /data/nur.db /data/backups/nur-$(date +%Y%m%d%H%M%S).db.bak`
- **Montar volumen en Railway**: en el servicio, agregá un Volume y montalo en `/data` (Default Mount Path). La app detecta ese path (`RAILWAY_VOLUME_MOUNT_PATH`) automáticamente.

## ¿Cómo aplico los cambios desde GitHub y los despliego?
1. **Abrí el Pull Request en GitHub**
   - Entrá a la pestaña **Pull requests**.
   - Hacé clic en el PR abierto y revisá la solapa **Files changed** para ver el diff.
2. **Mergeá el PR**
   - En el propio PR, pulsá el botón verde **Merge pull request** (o **Squash and merge**).
   - Confirmá el merge y, si querés, borrá la rama del PR cuando GitHub te lo proponga.
3. **Forzá/esperá el deploy en Railway**
   - Verificá que Railway apunte a la rama `main`. Si tenés auto-deploy activado, se lanzará solo.
   - Si no, abrí el servicio en Railway y pulsá **Deploy** manualmente.
4. **Seteá/confirmá variables de entorno en Railway** (Settings → Variables)
   - `SECRET_KEY` (recomendado en producción). Si falta, la app genera una y la guarda en `/data/secret_key.txt` para sobrevivir reinicios.
   - `ADMIN_USER`, `ADMIN_PASS`, `OP_USER`, `OP_PASS` (opcional: si faltan se generan credenciales efímeras y se muestran en logs).
   - Usuarios de solo lectura: crealos desde **Admin → Usuarios** con el rol `visor` si necesitás alguien que solo consulte estados.
5. **Revisá los logs del deploy**
   - Buscá mensajes de arranque y, si no configuraste credenciales, anotá las que se muestran en consola.
6. **Probá la app**
   - Abrí la URL pública. Si hiciste cambios de frontend, usá Ctrl+F5 para limpiar caché.

Si el deploy sigue fallando con un error de `SECRET_KEY`, confirmá que Railway pueda escribir en el volumen (`/data`) o definí la variable manualmente en Settings.
Abrí: http://127.0.0.1:5000

Usuarios (si la DB está vacía, se crean solos):
- admin / admin123*
- PSA / 123*

## Railway (simple)
Subí estos archivos al repo:
- app.py
- requirements.txt
- Procfile (o Dockerfile)
- runtime.txt (opcional)
- .gitignore

Variables recomendadas:
- SECRET_KEY (obligatorio)
- ADMIN_USER, ADMIN_PASS
- OP_USER, OP_PASS
- WHATSAPP_NUMBER (opcional) ej: 54911XXXXXXXXX

Start command (si te lo pide Railway):
`sh -c "gunicorn -w 2 -b 0.0.0.0:${PORT:-8080} app:app"`
