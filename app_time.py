import pandas as pd
from datetime import datetime, timedelta
import time
from whois import whois
from config import *

def calculate_app_time(df, timeout_minutes=APP_TIME_SESSION_TIMEOUT):
    # Convert timestamps to datetime
    df['Start Time'] = pd.to_datetime(df['Start Time'], unit='s')
    df['End Time'] = pd.to_datetime(df['End Time'], unit='s')
    
    # Filter for today only - from midnight to now
    today_start = pd.Timestamp.now().normalize()  # midnight
    today_end = pd.Timestamp.now()
    df = df[(df['Start Time'] >= today_start) & (df['Start Time'] <= today_end)]
    
    df = df.sort_values('Start Time')
    
    app_stats = {}
    timeout = timedelta(minutes=timeout_minutes)
    
    for ip, group in df.groupby('Source IP'):
        current_start = None
        last_activity = None
        total_time = timedelta()
        total_size = 0
        
        for _, row in group.iterrows():
            total_size += row['Total Size']
            if current_start is None:
                current_start = row['Start Time']
                last_activity = row['End Time']
            else:
                if row['Start Time'] - last_activity > timeout:
                    total_time += last_activity - current_start
                    current_start = row['Start Time']
                last_activity = max(last_activity, row['End Time'])
        
        if current_start is not None:
            total_time += last_activity - current_start
        
        app_stats[ip] = {
            'minutes': round(total_time.total_seconds() / 60, 2),
            'mb': round(total_size / (1024 * 1024), 2)
        }
    
    return app_stats

def monitor_app_time(update_interval=APP_TIME_UPDATE_INTERVAL):
    last_times = {}
    
    while True:
        try:
            df = pd.read_csv(UDP_LOG_FILE)
            current_stats = calculate_app_time(df)
            
            print("\033[H\033[J")
            print(f"App Usage Times")
            print("-" * 60)
            
            # Sort by time spent
            for ip, stats in sorted(current_stats.items(), key=lambda x: x[1]['minutes'], reverse=True):
                if stats['minutes'] > 0:
                    domain = whois(ip) or ip
                    minutes = stats['minutes']
                    hours = int(minutes // 60)
                    mins = int(minutes % 60)
                    time_str = f"{hours}h {mins}m" if hours > 0 else f"{mins}m"
                    mb_str = f"{stats['mb']:.1f}MB"
                    print(f"{domain} ({ip}): {time_str} | {mb_str}")
            
            last_times = current_stats
            time.sleep(update_interval)
            
        except KeyboardInterrupt:
            break
        except Exception as e:
            print(f"Error: {e}")
            time.sleep(update_interval)

if __name__ == "__main__":
    monitor_app_time()
