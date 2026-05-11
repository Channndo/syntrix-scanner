FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app

# Render SSH / dashboard shell: running user needs a .ssh directory (see render.com/docs/ssh).
# python:3.12-slim runs as root; without this, `render ssh` can fail with exit 255.
RUN mkdir -p /root/.ssh && chmod 700 /root/.ssh

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]