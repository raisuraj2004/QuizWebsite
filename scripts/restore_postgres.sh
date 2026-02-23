#!/usr/bin/env sh
set -eu

: "${DATABASE_URL:?DATABASE_URL is required}"
: "${BACKUP_FILE:?BACKUP_FILE is required}"

gunzip -c "$BACKUP_FILE" | psql "$DATABASE_URL"
echo "Restore completed from $BACKUP_FILE"
