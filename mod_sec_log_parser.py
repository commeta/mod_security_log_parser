#!/usr/bin/env python3
"""
mod_sec_log_parser.py
Project url: https://github.com/commeta/mod_security_log_parser

Copyright 2024 commeta <dcs-spb@ya.ru>

This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 2 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
MA 02110-1301, USA.
"""

import os
import re
import pymysql
from pymysql import MySQLError
from datetime import datetime

WATCH_DIR = "/var/log/httpd/modsec_audit/"
MERGED_LOG_FILE = "/var/log/httpd/modsec_merged.log"

regex_patterns = {
    'REQUEST_METHOD': re.compile(r'--[0-9a-f]+-B--\n([A-Z]+) '),
    'REQUEST_URI': re.compile(r'--[0-9a-f]+-B--\n[A-Z]+ (.+?) '),
    'REMOTE_ADDR': re.compile(r'--[0-9a-f]+-A--\n.*? ((?:[\d\.]+|[0-9a-fA-F:]+)) '), 
    'Host': re.compile(r'Host: (.+)'),
    'User-Agent': re.compile(r'User-Agent: (.+)'),
    'ruleId': re.compile(r'\[id "(\d+)"\]'),
    'msg': re.compile(r'\[msg "(.+?)"\]'),
    'data': re.compile(r'\[data "(.+?)"\]'),
    'unique_id': re.compile(r'\[.*?\] ([\w@-]+)'),
    'severity': re.compile(r'\[severity "(\w+)"\]'),
    'maturity': re.compile(r'\[maturity "(\d+)"\]'),
    'accuracy': re.compile(r'\[accuracy "(\d+)"\]'),
    'responce_header': re.compile(r'--[0-9a-f]+-F--\n(HTTP/\d\.\d \d{3} [^\r\n]+)'),
    'Engine-Mode': re.compile(r'Engine-Mode: "(.+)"'),
    'apache_error': re.compile(r'Apache-Error: (.+)'),
    'created_at': re.compile(r'\[(\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2} [+-]\d{4})\]')
}


def parse_log_file(file_path):
    with open(file_path, 'r', encoding='latin-1') as file:
        content = file.read()
    parsed_data = {}
    for key, pattern in regex_patterns.items():
        match = pattern.search(content)
        if match:
            parsed_data[key] = match.group(1)
        else:
            parsed_data[key] = None
    if not parsed_data['msg']:
        apache_error_match = regex_patterns['apache_error'].search(content)
        if apache_error_match:
            parsed_data['msg'] = apache_error_match.group(1)
    if parsed_data['created_at']:
        parsed_data['created_at'] = datetime.strptime(parsed_data['created_at'], '%d/%b/%Y:%H:%M:%S %z')

    with open(MERGED_LOG_FILE, 'a') as merged_file:
        merged_file.write(content + "\n")

    return parsed_data

def connect_to_db():
    try:
        connection = pymysql.connect(
            host='localhost',
            database='database',
            user='user',
            password='password'
        )
        return connection
    except MySQLError as e:
        print(f"Error while connecting to MySQL: {e}")
        return None

def sanitize_string(s):
    return re.sub(r'[^\w\s./~!\(\):@&=+$,?#%]+', ' ', s)

def validate_data(data):
    for key in data:
        if isinstance(data[key], str):
            data[key] = sanitize_string(data[key])
    
    return data

def insert_into_db(connection, data):
    cursor = connection.cursor()
    
    # Валидация данных перед вставкой
    data = validate_data(data)
        
    insert_query = """
    INSERT INTO logs (REQUEST_METHOD, REQUEST_URI, REMOTE_ADDR, ruleId, Host, msg, data, unique_id, severity, maturity, accuracy, User_Agent, responce_header, Engine_Mode, created_at)
    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
    """
    cursor.execute(insert_query, (
        data['REQUEST_METHOD'], data['REQUEST_URI'], data['REMOTE_ADDR'], data['ruleId'], data['Host'], data['msg'], 
        data['data'], data['unique_id'], data['severity'], data['maturity'], data['accuracy'], data['User-Agent'], 
        data['responce_header'], data['Engine-Mode'], data['created_at']
    ))
    connection.commit()

def main():
    connection = connect_to_db()
    if not connection:
        return
    

    for root, dirs, files in os.walk(WATCH_DIR, topdown=False):
        for file in files:
            file_path = os.path.join(root, file)
            parsed_data = parse_log_file(file_path)
            insert_into_db(connection, parsed_data)
            os.remove(file_path)
        
        for dir in dirs:
            dir_path = os.path.join(root, dir)
            if not os.listdir(dir_path):
                os.rmdir(dir_path)
        
    if connection.open:
        connection.close()

if __name__ == "__main__":
    main()
