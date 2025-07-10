import pandas as pd
from datetime import datetime, timedelta
import time
from whois import whois

def calculate_app_time(df, timeout_minutes=5):
    df['Start Time'] = pd.to_datetime(df['Start Time'], unit='s')
    df['End Time'] = pd.to_datetime(df['End Time'], unit='s')
    df = df.sort_values('Start Time')
    
    app_times = {}
    timeout = timedelta(minutes=timeout_minutes)
    
    for ip, group in df.groupby('Source IP'):
        current_start = None
        last_activity = None
        total_time = timedelta()
        
        for _, row in group.iterrows():
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
        app_times[ip] = round(total_time.total_seconds() / 60, 2)
    
    return app_times

def monitor_app_time(update_interval=1):
    last_times = {}
    
    while True:
        try:
            df = pd.read_csv("traffic_logs/udp_aggregated.csv")
            current_times = calculate_app_time(df)
            
            print("\033[H\033[J")
            print("App Usage Times (Updated Real-time):")
            print("-" * 60)
            
            for ip, minutes in sorted(current_times.items(), key=lambda x: x[1], reverse=True):
                if minutes > 0:
                    domain = whois(ip) or ip
                    change = ""
                    if ip in last_times:
                        diff = minutes - last_times[ip]
                        if diff > 0:
                            change = f" (+{diff:.1f}m)"
                    print(f"{domain} ({ip}): {minutes:.1f}m{change}")
            
            last_times = current_times
            time.sleep(update_interval)
            
        except KeyboardInterrupt:
            break
        except Exception as e:
            print(f"Error: {e}")
            time.sleep(update_interval)

if __name__ == "__main__":
    monitor_app_time()
