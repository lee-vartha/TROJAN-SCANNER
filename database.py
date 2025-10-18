import sqlite3
import os
from datetime import datetime

DB_PATH = "history.db"

def init_db():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            filename TEXT,
            yara_matches TEXT,
            vt_detections INTEGER,
            vt_result TEXT,
            timestamp TEXT
        )
 """)
    conn.commit()
    conn.close()

def save_scan(filename, yara_matches, vt_detections, vt_result):
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute(""" 
        INSERT INTO scans (filename, yara_matches, vt_detections, vt_result, timestamp)
                VALUES (?, ?, ?, ?, ?)
    """, (filename, yara_matches, vt_detections, vt_result, datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
    conn.commit()
    conn.close()
                