#!/bin/bash

WATCH_DIR="/var/log/httpd/modsec_audit/"
PID_FILE="/var/run/watch_create.pid"

check_running() {
    if [ -f "$PID_FILE" ]; then
        local pid=$(cat "$PID_FILE")
        if [ -d "/proc/$pid" ]; then
            echo "Скрипт уже запущен с PID $pid"
            exit 1
        else
            echo "Найден устаревший PID файл. Удаление..."
            rm -f "$PID_FILE"
        fi
    fi
}

write_pid() {
    echo $$ > "$PID_FILE"
}

cleanup() {
    rm -f "$PID_FILE"
    exit 0
}

trap cleanup SIGINT SIGTERM

check_running
write_pid

process_new_directory() {
    local NEW_DIR=$1
    local RELATIVE_PATH=${NEW_DIR#$WATCH_DIR}

    if [[ $RELATIVE_PATH == */* ]]; then
        # Это подкаталог второго уровня или глубже
        chmod 770 "$NEW_DIR"
        chown apache:fastsecure "$NEW_DIR"
        echo "New subdirectory detected: $NEW_DIR" >> /var/log/httpd/watch_dir.log
    else
        # Это каталог первого уровня
        find "$NEW_DIR" -type d -exec chmod 770 {} \; -exec chown apache:fastsecure {} \;
        echo "New top-level directory detected and processed recursively: $NEW_DIR" >> /var/log/httpd/watch_dir.log
    fi
}

(
    while true; do
        inotifywait -m -r -e create --format '%w%f' "$WATCH_DIR" | while read NEW_ITEM
        do
            if [ -d "$NEW_ITEM" ]; then
                process_new_directory "$NEW_ITEM"
            fi
        done
    done
) &
exit 0
