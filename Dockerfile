FROM python:3.12-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    DEBIAN_FRONTEND=noninteractive \
    ANALYSIS_RUNTIME_DIR=/tmp \
    UVICORN_HOST=127.0.0.1 \
    UVICORN_PORT=8080
RUN apt-get update \
 && apt-get install -y --no-install-recommends tshark ca-certificates libcap2-bin \
 && chmod 0755 /usr/bin/dumpcap \
 && setcap cap_net_raw=ep /usr/bin/dumpcap \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /srv/app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app ./app
COPY static ./static
RUN useradd --system --uid 10001 --home-dir /nonexistent --no-create-home packet
USER packet
EXPOSE 8080
CMD ["uvicorn", "app.main:app", "--no-access-log"]
