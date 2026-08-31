# Sandbox image for reproduction attempts.
#
# Design notes:
#   * Every dependency is installed at BUILD time. The container is run with
#     --network none, so a reproduction attempt can never reach the internet
#     and can never silently install a different version than the one under test.
#   * Each pinned version lands in its own --target directory rather than a venv:
#     same isolation for import purposes, a fraction of the build time.
#   * Runs as a non-root user. Proof-of-concept code in a vulnerability report is
#     untrusted input by definition; it is executed here and nowhere else.
FROM python:3.9-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

COPY corpus/environments.tsv /build/environments.tsv

# One dependency tree per (package, version) under test.
RUN set -eu; \
    mkdir -p /envs; \
    grep -v '^#' /build/environments.tsv | grep -v '^[[:space:]]*$' | while IFS="$(printf '\t')" read -r env_id pip_spec _rest; do \
        echo "==> $env_id ($pip_spec)"; \
        pip install --no-cache-dir --quiet --target "/envs/$env_id" "$pip_spec"; \
    done; \
    rm -rf /root/.cache

COPY slopgate/sandbox/entrypoint.py /opt/entrypoint.py

RUN useradd --create-home --shell /usr/sbin/nologin runner \
    && mkdir -p /work && chown runner:runner /work
USER runner
WORKDIR /work

ENTRYPOINT ["python", "/opt/entrypoint.py"]
