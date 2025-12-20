# NUR (Flask + Login + Roles)

## Local
```powershell
python -m venv venv
$env:SECRET_KEY="definí-una-clave-segura"
$env:ADMIN_USER="admin"
$env:ADMIN_PASS="cambiame"
$env:OP_USER="PSA"
$env:OP_PASS="cambiame"
Usuarios iniciales: si la DB está vacía se crearán al iniciar. Si faltan variables, se generan usuarios y contraseñas efímeras (solo para esa ejecución) y se muestran en la consola.
Variables recomendadas (definilas en producción; en local se generan claves/usuarios efímeros si faltan):
- SECRET_KEY

Variables opcionales:
```
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
