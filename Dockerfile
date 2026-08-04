FROM python:3.11-slim@sha256:f9fa7f851e38bfb19c9de3afbc4b86ae7176ea7aaf94535c31df5458d5849457 AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /action

COPY requirements.txt .
RUN pip install --no-cache-dir --require-hashes -r requirements.txt

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

# No lib/pii-shield.wasm any more: the engine ships inside the
# pii-shield-wasi wheel installed from requirements.txt, so it is already
# in the site-packages copied above. Re-adding a COPY here would fail the
# build (the file is deleted) and re-vendor what pip now delivers.
COPY src/ /staging/action/src/
COPY entrypoint.py /staging/action/

# --- Single layer on top of base ---
FROM python:3.11-slim@sha256:f9fa7f851e38bfb19c9de3afbc4b86ae7176ea7aaf94535c31df5458d5849457

LABEL maintainer="GuardSpine <support@guardspine.io>"
LABEL org.opencontainers.image.source="https://github.com/DNYoussef/codeguard-action"
LABEL org.opencontainers.image.description="AI-aware code governance with verifiable evidence bundles"

COPY --from=builder /staging/ /

WORKDIR /action

ENTRYPOINT ["python", "/action/entrypoint.py"]
