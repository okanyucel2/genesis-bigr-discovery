#!/usr/bin/env bash
# Dev wrapper: runs alembic against local SQLite by default.
# Override with DATABASE_URL env var for production.
set -euo pipefail
DATABASE_URL="${DATABASE_URL:-sqlite:///$HOME/.bigr/bigr.db}" \
  alembic "$@"
