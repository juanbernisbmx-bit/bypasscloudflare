# Imagen que corre la herramienta dentro de la red del lab.
# Contexto de build = raiz del repo (ver docker-compose.yml).
FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
