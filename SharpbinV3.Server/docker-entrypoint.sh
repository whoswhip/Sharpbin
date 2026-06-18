#!/bin/sh
set -eu

APP_USER="${APP_USER:-appuser}"
APP_GROUP="${APP_GROUP:-appuser}"

fix_path_owner() {
    target="$1"

    if [ -z "$target" ]; then
        return
    fi

    mkdir -p "$target"
    chown -R "$APP_USER:$APP_GROUP" "$target"
}

connection_string="${ConnectionStrings__DefaultConnection:-}"
db_path=""

case "$connection_string" in
    *"Data Source="*)
        db_path="${connection_string#*Data Source=}"
        db_path="${db_path%%;*}"
        ;;
esac

if [ "$(id -u)" = "0" ]; then
    fix_path_owner "/app/data"

    if [ -n "$db_path" ]; then
        db_dir="$(dirname "$db_path")"
        fix_path_owner "$db_dir"
    fi

    if [ -n "${DATA_PROTECTION_KEY_PATH:-}" ]; then
        fix_path_owner "$DATA_PROTECTION_KEY_PATH"
    fi

    exec runuser -u "$APP_USER" -- "$@"
fi

exec "$@"
