import os
from glob import glob

# get the latest log file name by time
def get_latest_log_tcp():
    files = glob("./traffic_logs/tcp_aggregated_*.csv")
    if not files:
        return None
    # Return the most recently created file
    return max(files, key=os.path.getctime)

def get_latest_log_udp():
    files = glob("./traffic_logs/udp_aggregated_*.csv")
    if not files:
        return None
    # Return the most recently created file
    return max(files, key=os.path.getctime)