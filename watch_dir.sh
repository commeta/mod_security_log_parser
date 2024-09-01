#!/bin/bash

WATCH_DIR="/var/log/httpd/modsec_audit/"
PID_FILE="/var/run/watch_create.pid"

# Check for running instances
check_running() {
    if [ -f "$PID_FILE" ]; then
        pid=$(cat "$PID_FILE")
        
        if [ -d "/proc/$pid" ]; then
			echo "Script already running with PID $pid. Sending SIGTERM."
			stop_inotifywait
        fi
    fi
}

# Function to find and send SIGTERM to inotifywait process
stop_inotifywait() {
	ps aux | grep "inotifywait -m -r -e create --format %w%f $WATCH_DIR" | grep -v grep | awk '{print $2}'| while read pid; do
		kill -SIGTERM "$pid"
		echo "Sending SIGTERM to inotifywait process with PID $pid."
	done
}

# Write current PID to file
write_pid() {
	echo $$ > "$PID_FILE"
}

# Cleanup on interrupt or termination
cleanup() {
	rm -f "$PID_FILE"
	stop_inotifywait
	exit 0
}

# Trap signals for clean exit
trap cleanup SIGINT SIGTERM

# Check for existing instances and write PID
check_running
write_pid

# Monitor the audit directory for new files
inotifywait -m -r -e create --format '%w%f' "$WATCH_DIR" | while read -r line; do
	if [ -d "$line" ]; then
		chmod 770 "$line"
		chown apache:fastsecure "$line"
	fi
done


# Exit the script
exit 0

