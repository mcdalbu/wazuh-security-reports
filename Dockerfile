FROM docker.io/library/python:3.12-slim-bookworm
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 HOME=/tmp
RUN apt-get update && apt-get install -y --no-install-recommends fonts-dejavu-core ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 10001 reports && useradd --uid 10001 --gid reports --no-create-home reports \
    && mkdir /data && chown reports:reports /data
WORKDIR /app
COPY requirements-web.txt ./
RUN pip install --no-cache-dir -r requirements-web.txt
COPY wazuh_report.py ./
COPY assets/timbrado_confidencial.pdf ./assets/timbrado_confidencial.pdf
COPY web ./web
USER 10001:10001
EXPOSE 8000
# One worker is intentional: PDF rendering is serialized with an in-process lock.
CMD ["gunicorn", "--bind", "0.0.0.0:8000", "--workers", "1", "--threads", "4", "--timeout", "360", "--worker-tmp-dir", "/dev/shm", "web.app:create_app()"]
