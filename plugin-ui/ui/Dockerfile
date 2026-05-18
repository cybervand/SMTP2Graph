FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py .
COPY templates ./templates

ENV UI_PORT=16666
EXPOSE 16666

CMD ["sh", "-c", "gunicorn --bind 0.0.0.0:${UI_PORT} --workers 2 --preload --access-logfile - app:app"]
