FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /app

COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py /app/app.py

# Railway sets PORT automatically
CMD sh -c "gunicorn -w 2 -b 0.0.0.0:${PORT:-8080} app:app"
