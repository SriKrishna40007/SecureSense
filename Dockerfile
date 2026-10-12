FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

RUN groupadd --system securesense \
    && useradd --system --gid securesense --home-dir /app securesense

COPY pyproject.toml README.md ./
COPY src/ ./src/

RUN pip install --no-cache-dir .

COPY devices/ ./devices/
COPY scenarios/ ./scenarios/

USER securesense

ENTRYPOINT ["securesense"]
CMD ["report"]
