import csv
from datetime import datetime
import pandas as pd

DNS_LOG_FILE = "traffic_logs/dns.csv"
_domain_cache = {}

def tag_ip(ip, domain):
    with open(DNS_LOG_FILE, mode="a", newline='') as file:
        writer = csv.writer(file)
        writer.writerow([datetime.now().timestamp(), domain, ip])
    _domain_cache[ip] = domain
    
def whois(ip):
    if ip in _domain_cache:
        return _domain_cache[ip]
        
    try:
        df = pd.read_csv(DNS_LOG_FILE)
        df = df[df['IP Address'] == ip]
        if df.empty:
            _domain_cache[ip] = None
            return None
        else:
            domain = df.iloc[0]['Domain Name']
            _domain_cache[ip] = domain
            return domain
    except Exception as e:
        _domain_cache[ip] = None
        return None
    