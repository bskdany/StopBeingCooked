import pandas as pd
import time
from firewall import blacklist_ip_thread, get_blacklist
from notifications import send_push_message
from whois import whois
from datetime import datetime

ROLLING_WINDOW_SIZE_MIN = 1
MIN_DATA_POINTS = 5

# Create a rolling window of the IPs excluding the blacklist
def get_rolling_window(df, start_time, end_time, blacklist):
    return df[(df['Start Time'] >= start_time) & 
              (df['Start Time'] <= end_time) & 
              (~df['Source IP'].isin(blacklist))]

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
        print(seen)

    for ip in seen:
        if seen[ip][0] >= MIN_DATA_POINTS: 
            blacklist_ip_thread(ip, ROLLING_WINDOW_SIZE_MIN * 60)
            return True
    return False


def detect_doomscrolling():
    update_interval = 1
    last_doomscroll_time = 0

    while True:
        df = pd.read_csv("traffic_logs/udp_aggregated.csv")
        
        end_time = datetime.now().timestamp()
        start_time = max(end_time - ROLLING_WINDOW_SIZE_MIN * 60, last_doomscroll_time)

        window_df = get_rolling_window(df, start_time, end_time, get_blacklist())

        if(analyse_window_instagram(window_df)):
            send_push_message("Doomscrolling Detected")

        time.sleep(update_interval)
                
if __name__ == "__main__":
    detect_doomscrolling()
