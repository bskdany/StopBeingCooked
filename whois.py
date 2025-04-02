import csv
from datetime import datetime
import pandas as pd

DNS_LOG_FILE = "traffic_logs/dns.csv"

def tag_ip(ip, domain):
    with open(DNS_LOG_FILE, mode="a", newline='') as file:
        writer = csv.writer(file)
        writer.writerow([datetime.now().timestamp(), domain, ip])
    
def whois(ip):
    df = pd.read_csv(DNS_LOG_FILE)
    df = df[df['IP'] == ip]
    if df.empty:
        return None
    else:
        return df.iloc[0]['Domain']
    