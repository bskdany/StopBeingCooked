import os
import logging
from datetime import datetime

# Create logs directory if it doesn't exist
if not os.path.exists("traffic_logs"):
    os.makedirs("traffic_logs")

# Configure console-only logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

from config import *
import csv

if(not os.path.isfile(UDP_LOG_FILE)):
    with open(UDP_LOG_FILE, mode="w", newline='') as file:
        writer = csv.writer(file)
        writer.writerow(["Start Time", "End Time", "Source IP", "Source Port", "Destination IP", "Destination Port", "Total Size", "Total Packets"])

if(not os.path.isfile(TCP_LOG_FILE)):
    with open(TCP_LOG_FILE, mode="w", newline='') as file:
        writer = csv.writer(file)
        writer.writerow(["Start Time", "End Time", "Source IP", "Source Port", "Destination IP", "Destination Port", "Total Size", "Total Packets"])

if(not os.path.isfile(DNS_LOG_FILE)):
    with open(DNS_LOG_FILE, mode="w", newline='') as file:
        writer = csv.writer(file)
        writer.writerow(["Timestamp", "Domain Name", "IP Address"])

import threading 
from interceptor import intercept_traffic
from detector import detect_doomscrolling
from app_time import monitor_app_time


def main():
    traffic_interceptot_thread = threading.Thread(target=intercept_traffic, daemon=True, name="TrafficInterceptor")
    doomscrolling_detector_thread = threading.Thread(target=detect_doomscrolling, daemon=True, name="DoomscrollingDetector")
    # app_time_monitor_thread = threading.Thread(target=monitor_app_time, daemon=True, name="AppTimeMonitor")

    traffic_interceptot_thread.start()
    doomscrolling_detector_thread.start()
    try:
        while True:
            threading.Event().wait()
    except KeyboardInterrupt:
        logger.info("Received shutdown signal")
        logger.info("Shutting down StopBeingCooked...")

if __name__ == "__main__":
    main()