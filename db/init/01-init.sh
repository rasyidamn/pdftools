#!/bin/sh
# Dijalankan otomatis oleh image postgres hanya saat volume data masih kosong.
# (Skrip ini boleh di-source maupun dieksekusi, jadi tanpa 'exit'.)
set -e
psql -v ON_ERROR_STOP=1 -v app_pw="$APP_DB_PASSWORD" \
     --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" \
     -f /docker-entrypoint-initdb.d/schema.sql.in