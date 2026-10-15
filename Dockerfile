FROM python:3.12-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    DEBIAN_FRONTEND=noninteractive \
    CAPTURE_DIR=/data
RUN apt-get update \
 && apt-get install -y --no-install-recommends tshark ca-certificates \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /srv/app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app ./app
COPY static ./static
RUN useradd --system --uid 10001 --home-dir /nonexistent --no-create-home packet \
 && mkdir -p /data && chown packet:packet /data
USER packet
EXPOSE 8080
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8080", "--no-access-log"]
