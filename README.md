# NUR (Flask + Login + Roles)

## Local
```powershell
python -m venv venv
.env\Scripts\activate
pip install -r requirements.txt
$env:FLASK_DEBUG="1"
python app.py
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
