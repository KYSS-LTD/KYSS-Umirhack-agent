FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# Install diagnostic tools in isolated image layer for agent tasks and troubleshooting
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
      procps \
      iproute2 \
      iputils-ping \
      net-tools \
      dnsutils \
      curl \
      ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN groupadd -g 10001 appgroup \
    && useradd -u 10001 -g appgroup -m -s /usr/sbin/nologin appuser \
    && mkdir -p /agent-data \
    && chown -R appuser:appgroup /agent-data /app

RUN pip install --no-cache-dir httpx==0.27.2 pynacl==1.5.0

COPY agent.py diagnostics.py /app/

USER appuser

CMD ["python", "/app/agent.py"]
