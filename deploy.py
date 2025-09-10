import os
from datetime import datetime
from config import *
import csv
import threading 
from interceptor import intercept_traffic
from detector import detect_doomscrolling
from app_time import monitor_app_time
from sqlite import init_db
from logger import logger

def main():
    init_db()

    traffic_interceptot_thread = threading.Thread(target=intercept_traffic, daemon=True, name="TrafficInterceptor")
    doomscrolling_detector_thread = threading.Thread(target=detect_doomscrolling, daemon=True, name="DoomscrollingDetector")
    # app_time_monitor_thread = threading.Thread(target=monitor_app_time, daemon=True, name="AppTimeMonitor")

    traffic_interceptot_thread.start()
    doomscrolling_detector_thread.start()
    try:
        while True:
            threading.Event().wait()
    except KeyboardInterrupt:
        logger.info("Shuttind down...")
        traffic_interceptot_thread.join()
        doomscrolling_detector_thread.join()
        logger.info("shut down succesful")

if __name__ == "__main__":
    main()