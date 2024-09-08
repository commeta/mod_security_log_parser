#!/bin/bash

# Set variables
WATCH_DIR="/var/log/httpd/modsec_audit/"
LOG_FILE="/var/lib/modsecurity_recedive/modsec_recedive.dat" 
RECEDIVE_FILE="/var/log/httpd/modsec_recedive.log"
TIMEOUT=60  # minute in seconds
PID_FILE="/var/run/modsec_recedive.pid"
ATTACK_THRESHOLD=10  # Number of attacks before logging to recedive file
old_timestamp=0

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


if [ ! -d $(dirname "$LOG_FILE") ]; then
	mkdir -p $(dirname "$LOG_FILE")
fi


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
	local timestamp
	local status_code
	
	status_code=$(grep "HTTP/1.1" "$log_file" | awk '{print $2}') 
	
	if [[ $status_code -eq 403 ]]; then # Check for 403 status code
		ip_address=$(grep "X-Real-IP" "$log_file" | awk '{print $2}')
  
		# Проверка ip_address на пустую строку
		if [[ -z "$ip_address" ]]; then
			return 1
		fi
	
		if grep -q "^$ip_address " "$LOG_FILE"; then
			error_count=$(grep "^$ip_address " "$LOG_FILE" | awk '{print $2}')
			
			# Проверка error_count
			if [[ $error_count -lt $ATTACK_THRESHOLD ]]; then
				timestamp=$(date +%s)
				error_count=$((error_count + 1))
				
				sed -i "s/^$ip_address .*/$ip_address $error_count $timestamp/" "$LOG_FILE"
        
				if [[ $error_count -eq $ATTACK_THRESHOLD ]]; then 
					echo "$ip_address - $(date +'%Y-%m-%d %H:%M:%S')" >> "$RECEDIVE_FILE"
				fi
			else
				# Получаем текущий timestamp из файла
				timestamp=$(grep "^$ip_address " "$LOG_FILE" | awk '{print $3}')
				error_count=$((error_count + 1))
				
				sed -i "s/^$ip_address .*/$ip_address $error_count $timestamp/" "$LOG_FILE"
        
				if [[ $((error_count % ATTACK_THRESHOLD)) -eq 0 ]]; then 
					echo "$ip_address - $(date +'%Y-%m-%d %H:%M:%S')" >> "$RECEDIVE_FILE"
				fi        
			fi	
		else
			timestamp=$(date +%s)
			echo "$ip_address 1 $timestamp" >> "$LOG_FILE"
		fi
	fi
}


# Monitor the audit directory for new files
inotifywait -m -r -e create --format '%w%f' "$WATCH_DIR" | while read -r line; do
	if [ -f "$line" ]; then
		analyze_log_file "$line"
		
		# Очистка лога после обработки файла
		current_timestamp=$(date +%s)
		
		if [[ $old_timestamp -ne $current_timestamp ]]; then
			threshold_timestamp=$((current_timestamp - TIMEOUT))
			
			# Перебираем все строки в файле
			while read -r line; do
				# Извлекаем timestamp из строки
				timestamp=$(echo "$line" | awk '{print $3}')
				
				# Проверяем, истек ли timestamp
				if [[ $timestamp -lt $threshold_timestamp ]]; then
					# Удаляем строку из файла
					sed -i "/^$line$/d" "$LOG_FILE"
				fi
			done < "$LOG_FILE"   
			
			old_timestamp=$current_timestamp
   			
      			# запуск парсера   
			/opt/mod_sec_log_parser.py &
		fi
	else
		chmod 770 "$line"
		chown apache:fastsecure "$line"
	fi
done


# Exit the script
exit 0
