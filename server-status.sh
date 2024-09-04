#!/bin/bash

# Файл для хранения состояния режима замедления
STATE_FILE="/var/run/server_slowdown_active"

# Функция для логирования
log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" >> /var/log/server_monitor.log
}

# Получить вывод от curl
server_status=$(curl -s http://127.0.0.1:81/server-status?auto)

if [ $? -ne 0 ]; then
    log "Failed to get server status"
    exit 1
fi

# Извлечь CPU load
cpu_load=$(echo "$server_status" | grep "CPULoad" | awk '{print $2}')

# Извлечь ReqPerSec
requests_per_sec=$(echo "$server_status" | grep "ReqPerSec" | awk '{print $2}')

# Замедление новых запросов
function slow_down_requests {
  if [ ! -f "$STATE_FILE" ]; then
    iptables -A INPUT -p tcp --dport 80 -m recent --set --name SLOW_DOWN
    iptables -A INPUT -p tcp --dport 80 -m recent --update --seconds 60 --hitcount 5 --name SLOW_DOWN -j DROP
    touch "$STATE_FILE"
    log "Activated request slowdown"
  fi
}

function restore_requests {
  if [ -f "$STATE_FILE" ]; then
    iptables -D INPUT -p tcp --dport 80 -m recent --set --name SLOW_DOWN
    iptables -D INPUT -p tcp --dport 80 -m recent --update --seconds 60 --hitcount 5 --name SLOW_DOWN -j DROP
    rm "$STATE_FILE"
    log "Deactivated request slowdown"
  fi
}


# Проверка Requests per second
if [[ ! -z "$requests_per_sec" && $(bc <<< "$requests_per_sec > 5.1") -eq 1 ]]; then
	# Проверка CPU load
	if [[ ! -z "$cpu_load" && $(bc <<< "$cpu_load > .5") -eq 1 ]]; then
	  slow_down_requests
	fi
fi

# Проверка на стабилизацию
if [ -f "$STATE_FILE" ]; then
  if [[ -z "$cpu_load" ]]; then
    restore_requests
  else
	  if [[ $(bc <<< "$cpu_load <= .5") -eq 1 && ! -z "$requests_per_sec" && $(bc <<< "$requests_per_sec <= 5.1") -eq 1 ]]; then
		restore_requests
	  fi
  fi
fi
