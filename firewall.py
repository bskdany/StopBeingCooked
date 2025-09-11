import subprocess
import threading
import time

blacklist = set()

def blacklist_ip(ip_address, duration_seconds=10):
    def add_rule():
        if ip_address not in blacklist:
            blacklist.add(ip_address)
            subprocess.run(["sudo", "iptables", "-I", "FORWARD", "-s", ip_address, "-j", "DROP"])
            print(f"Added block for incoming traffic from {ip_address}")

    def remove_rule():
        blacklist.remove(ip_address)
        subprocess.run(["sudo", "iptables", "-D", "FORWARD", "-s", ip_address, "-j", "DROP"])
        print(f"Removed block for incoming traffic from {ip_address}")

    try:
        add_rule()
        timer = threading.Timer(duration_seconds, remove_rule)
        timer.start()

    except subprocess.CalledProcessError as e:
        print(f"Error blacklisting ip ${ip_address}: {e}")
    
def get_blacklist():
    return blacklist

def blacklist_ip_thread(ip_address, duration_seconds=10):
    thread = threading.Thread(target=blacklist_ip, args=[ip_address, duration_seconds])
    thread.start()

def clean_blacklist():
    for ip_address in blacklist:
        remove_rule(ip_address)

if __name__ == "__main__":
    ip_to_limit = ""

    blacklist_ip_thread(ip_to_limit)

    for i in range(10):
        print(f"Main thread: {i}")
        time.sleep(1)
