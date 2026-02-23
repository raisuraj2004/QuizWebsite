#!/usr/bin/env sh
set -eu

: "${DATABASE_URL:?DATABASE_URL is required}"
: "${BACKUP_FILE:=backup_$(date +%Y%m%d_%H%M%S).sql.gz}"

pg_dump "$DATABASE_URL" | gzip > "$BACKUP_FILE"
echo "Backup written to $BACKUP_FILE"
