FROM python:3.11-slim AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /action

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Stage everything into /staging so the final image is a single COPY
RUN mkdir -p /staging/usr/bin \
    /staging/usr/lib/git-core \
    /staging/usr/share/git-core \
    /staging/usr/local/lib/python3.11/site-packages \
    /staging/usr/local/bin \
    /staging/action && \
    cp /usr/bin/git /staging/usr/bin/ && \
    cp -r /usr/lib/git-core/* /staging/usr/lib/git-core/ && \
    cp -r /usr/share/git-core/* /staging/usr/share/git-core/ && \
    cp -r /usr/local/lib/python3.11/site-packages/* /staging/usr/local/lib/python3.11/site-packages/ && \
    cp -r /usr/local/bin/* /staging/usr/local/bin/

# Copy libpcre2 (git runtime dependency)
RUN cp /usr/lib/*-linux-gnu/libpcre2-8.so* /staging/usr/lib/ 2>/dev/null; true

COPY src/ /staging/action/src/
COPY lib/pii-shield.wasm /staging/action/lib/pii-shield.wasm
COPY rubrics/ /staging/action/rubrics/
COPY entrypoint.py /staging/action/

# --- Single layer on top of base ---
FROM python:3.11-slim

LABEL maintainer="GuardSpine <support@guardspine.io>"
LABEL org.opencontainers.image.source="https://github.com/DNYoussef/codeguard-action"
LABEL org.opencontainers.image.description="AI-aware code governance with verifiable evidence bundles"

COPY --from=builder /staging/ /

WORKDIR /action

ENTRYPOINT ["python", "/action/entrypoint.py"]
