import pandas as pd
import time
from firewall import blacklist_ip_thread, get_blacklist
from notifications import send_push_message
from whois import whois
from datetime import datetime
from config import *
from logger import logger
import sqlite3

def packet_size_to_mb(packet_size):
    return round(packet_size / (1024 * 1024), 1)

def analyse_window_instagram(df):
    seen = dict()

    for index, row in df.iterrows():
        timestamp = row['Start Time']
        src_ip = row['Source IP']
        total_size = row['Total Size']

        if src_ip not in seen:
            domain = whois(src_ip)
            if domain and "instagram" in domain:
                seen[src_ip] = [0, domain]
        else:
            seen[src_ip][0] += 1
    
    if(len(seen) > 0):
        logger.info(f"Doomscrolling detected for {len(seen)} users")

    for ip in seen:
        if seen[ip][0] >= DOOMSCROLLING_CHECK_MIN_DATA_POINTS: 
            blacklist_ip_thread(ip, ROLLING_WINDOW_SIZE_MIN * 60)
            return True
    return False




def detect_doomscrolling():
    last_doomscroll_time = 0
    while True:
        sqlite_conn = sqlite3.connect('traffic.db')
        cursor = sqlite_conn.cursor()

        end_time = datetime.now().timestamp()
        # this is here so that if doomscrolling is detected for a time period, we don't check for it again
        start_time = max(end_time - DOOMSCROLLING_CHECK_ROLLING_WINDOW_SIZE, last_doomscroll_time)

        cursor.execute('''
            SELECT start_time as "Start Time", source_ip as "Source IP", total_size as "Total Size"
            FROM udp
            WHERE start_time >= ?
        ''', (start_time,))
        rows = cursor.fetchall()
        sqlite_conn.close()

        df = pd.DataFrame(rows, columns=["Start Time", "Source IP", "Total Size"])
        
        if(analyse_window_instagram(df)):
            logger.info("Doomscrolling detected for user ")
            send_push_message("Doomscrolling Detected")

        time.sleep(DOOMSCROLLING_CHECK_UPDATE_INTERVAL)
                
if __name__ == "__main__":
    detect_doomscrolling()
