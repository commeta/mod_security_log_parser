#!/bin/bash

# Set variables
WATCH_DIR="/var/log/httpd/modsec_audit/"
LOG_FILE="/var/log/httpd/modsec_attack.log"
RECEDIVE_FILE="/var/log/httpd/modsec_recedive.log"
TIMEOUT=600  # 10 minutes in seconds
PID_FILE="/var/run/modsec_recedive.pid"
ATTACK_THRESHOLD=10  # Number of attacks before logging to recedive file

# Check for running instances
check_running() {
  if [ -f "$PID_FILE" ]; then
    pid=$(cat "$PID_FILE")
    if [ -d "/proc/$pid" ]; then
      echo "Script already running with PID $pid"
      exit 1
    else
      echo "Found stale PID file. Removing..."
      rm -f "$PID_FILE"
    fi
  fi
}

# Write current PID to file
write_pid() {
  echo $$ > "$PID_FILE"
}

# Cleanup on interrupt or termination
cleanup() {
  rm -f "$PID_FILE"
  exit 0
}

# Trap signals for clean exit
trap cleanup SIGINT SIGTERM

# Check for existing instances and write PID
check_running
write_pid

# Ensure log files exist
if [ ! -f "$LOG_FILE" ]; then
  touch "$LOG_FILE"
fi

if [ ! -f "$RECEDIVE_FILE" ]; then
  touch "$RECEDIVE_FILE"
fi

# Analyze ModSecurity audit log files
analyze_log_file() {
  local log_file="$1"
  local ip_address
  local error_count
  local timestamp=$(date +%s)

  # Extract IP address from audit log
  ip_address=$(grep "X-Real-IP" "$log_file" | awk '{print $2}')

  # Check if IP address exists in attack log
  if grep -q "^$ip_address " "$LOG_FILE"; then
    error_count=$(grep "^$ip_address " "$LOG_FILE" | awk '{print $2}')
    error_count=$((error_count + 1))
    sed -i "s/^$ip_address .*/$ip_address $error_count $timestamp/" "$LOG_FILE"
  else
    # Add new IP address to attack log
    echo "$ip_address 1 $timestamp" >> "$LOG_FILE"
  fi

  # Log recedive if attack threshold is reached
  if [[ $(grep "^$ip_address " "$LOG_FILE" | awk '{print $2}') -eq $ATTACK_THRESHOLD ]]; then
    echo "$ip_address - $(date +'%Y-%m-%d %H:%M:%S')" >> "$RECEDIVE_FILE"
  fi
}

inotifywait -m -r -e create --format '%w%f' "$WATCH_DIR" | while read -r line; do
  if [ -f "$line" ]; then
    analyze_log_file "$line"
  else
    chmod 770 "$line"
    chown apache:fastsecure "$line"
  fi
done &

# Clean up old entries from the attack log
while true; do
  current_timestamp=$(date +%s)
  threshold_timestamp=$((current_timestamp - TIMEOUT))
  sed -i "/^.* $threshold_timestamp$/d" "$LOG_FILE"
  sleep $TIMEOUT
done &

# Exit the script
exit 0
