# Network configs
PACKET_SIZE_THRESHOLD = 10  # requests with less than this amount of packets are not saved
INTERFACE_NAME = "eth0"  # network interface to monitor
UDP_TIMEOUT = 0.1  # timeout for UDP packet aggregation

# File paths
UDP_LOG_FILE = "./traffic_logs/udp_aggregated.csv"
TCP_LOG_FILE = "./traffic_logs/tcp_aggregated.csv"
DNS_LOG_FILE = "./traffic_logs/dns.csv"

# IP filtering
IGNORE_LOCAL_IPS = True  # whether to ignore packets from local IPs (192.168.*)

# App time tracking
APP_TIME_UPDATE_INTERVAL = 1  # how often to update the app time display (seconds)
APP_TIME_SESSION_TIMEOUT = 5  # minutes of inactivity before considering a new session 

# Doomscrolling detection
ROLLING_WINDOW_SIZE_MIN = 1
MIN_DATA_POINTS = 5