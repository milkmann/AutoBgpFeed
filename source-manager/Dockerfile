FROM python:3.12-slim

WORKDIR /app

RUN pip install --no-cache-dir fastapi uvicorn httpx dnspython jinja2 python-multipart pytest

RUN python -c "import os, urllib.request; \
os.makedirs('/app/static/vendor/fonts', exist_ok=True); \
files = { \
  '/app/static/vendor/bootstrap.min.css': 'https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css', \
  '/app/static/vendor/bootstrap.bundle.min.js': 'https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/js/bootstrap.bundle.min.js', \
  '/app/static/vendor/bootstrap-icons.min.css': 'https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.3/font/bootstrap-icons.min.css', \
  '/app/static/vendor/fonts/bootstrap-icons.woff2': 'https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.3/font/fonts/bootstrap-icons.woff2', \
  '/app/static/vendor/fonts/bootstrap-icons.woff': 'https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.3/font/fonts/bootstrap-icons.woff', \
  '/app/static/vendor/chart.umd.min.js': 'https://cdn.jsdelivr.net/npm/chart.js@4.4.3/dist/chart.umd.min.js', \
}; \
[urllib.request.urlretrieve(u, p) for p, u in files.items()]"

COPY app /app/app
COPY templates /app/templates
COPY tests /app/tests

EXPOSE 8080

CMD ["python", "-m", "uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8080", "--proxy-headers", "--forwarded-allow-ips", "*"]
