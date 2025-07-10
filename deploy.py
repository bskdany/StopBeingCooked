import threading 
from interceptor import intercept_traffic
from detector import detect_doomscrolling
from app_time import monitor_app_time

def main():
    traffic_interceptot_thread = threading.Thread(target=intercept_traffic, daemon=True)
    # doomscrolling_detector_thread = threading.Thread(target=detect_doomscrolling, daemon=True)
    app_time_monitor_thread = threading.Thread(target=monitor_app_time, daemon=True)

    traffic_interceptot_thread.start()
    # doomscrolling_detector_thread.start()
    app_time_monitor_thread.start()

    try:
        while True:
            threading.Event().wait()
    except KeyboardInterrupt:
        print("Shutting down...")

if __name__ == "__main__":
    main()