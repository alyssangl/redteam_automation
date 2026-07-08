# The lgg_automation framework (orchestrator + stage subagents).
# It does NOT run Metasploit locally — it drives the Kali container over SSH/RPC.
FROM python:3.10-slim

# build-essential covers native wheels (chromadb/onnxruntime deps); ssh client
# is used by paramiko indirectly is not required, but keep git for pip VCS installs.
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install deps first for layer caching.
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Code is also bind-mounted in docker-compose for live editing; this COPY makes
# the image self-contained for CI / standalone runs.
COPY . .

# Associate this GHCR package with its source repo (GHCR auto-links on push).
LABEL org.opencontainers.image.source=https://github.com/bullyee/redteam_automation \
      org.opencontainers.image.description="lgg_automation framework (LangGraph orchestrator + stage subagents) — drives the Kali container over SSH/RPC"

ENV PYTHONUNBUFFERED=1 \
    PYTHONIOENCODING=utf-8

# Interactive by default. Run a scenario with, e.g.:
#   docker compose run --rm app python experiments/live_test_continuum.py
#   docker compose run --rm app python tests/run_offline.py
CMD ["bash"]
