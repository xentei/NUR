# NUR (Flask + Login + Roles)

## Local
```powershell
python -m venv venv
$env:SECRET_KEY="definí-una-clave-segura"
$env:ADMIN_USER="admin"
$env:ADMIN_PASS="cambiame"
$env:OP_USER="PSA"
$env:OP_PASS="cambiame"
Usuarios iniciales: si la DB está vacía se crearán al iniciar. Si faltan variables, se generan usuarios y contraseñas efímeras (solo para esa ejecución) y se muestran en la consola. Si no definís SECRET_KEY, la app genera una y la guarda en `instance/secret_key.txt` (o en el volumen `/data` en Railway) para que no falle el arranque y se mantenga entre reinicios locales.
Variables recomendadas (definilas en producción; en local se generan claves/usuarios efímeros si faltan):
- SECRET_KEY

Variables opcionales:

## ¿Cómo aplico los cambios desde GitHub y los despliego?
1. **Abrí el Pull Request en GitHub y pulsá “Merge”** (o “Squash and merge”). Esto deja el código actualizado en la rama principal.
2. **Verificá que Railway use la rama principal**. Si tenés auto-deploy, el deploy arranca solo. Si no, entrá a Railway y hacé clic en “Deploy” en el servicio.
3. **Chequeá variables de entorno** en Railway (Settings → Variables):
   - `SECRET_KEY` (recomendado en producción). Si no está, la app generará una y la guardará en el volumen `/data/secret_key.txt` para no fallar.
   - `ADMIN_USER`, `ADMIN_PASS`, `OP_USER`, `OP_PASS` (opcional: si faltan, se generan usuarios efímeros y se muestran en logs).
4. **Mirar los logs del deploy**. Si todo salió bien, deberías ver mensajes de arranque y, si faltaban credenciales, las claves generadas para esa instancia.
5. **Probar la app** entrando a la URL pública. Si agregaste nuevas plantillas o assets, forzá un refresh con Ctrl+F5 para evitar caché.

Si el deploy sigue fallando con un error de `SECRET_KEY`, confirmá que Railway pueda escribir en el volumen (`/data`) o definí la variable manualmente en Settings.
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
