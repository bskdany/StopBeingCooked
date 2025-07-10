from scapy.all import sniff, IP, IPv6, Ether, TCP, UDP, wrpcap, DNS, DNSQR, DNSRR
import csv
from datetime import datetime
import threading
import sys
import os
from whois import tag_ip
from config import *

PACKET_SIZE_TRESHOLD = 100 # requests with less than this amount of packest are not saved

# Generate unique timestamp for this recording session
# udp_log_file = f"./traffic_logs/udp_aggregated.csv"
# tcp_log_file = f"./traffic_logs/tcp_aggregated.csv"
# dns_log_file = f"./traffic_logs/dns.csv"

if(not os.path.isfile(UDP_LOG_FILE)):
    with open(UDP_LOG_FILE, mode="w", newline='') as file:
        writer = csv.writer(file)
        writer.writerow(["Start Time", "End Time", "Source IP", "Destination Port", "Total Size", "Total Packets"])

if(not os.path.isfile(TCP_LOG_FILE)):
    with open(TCP_LOG_FILE, mode="w", newline='') as file:
        writer = csv.writer(file)
        writer.writerow(["Start Time", "End Time", "Source IP", "Destination Port", "Total Size", "Total Packets"])

if(not os.path.isfile(DNS_LOG_FILE)):
    with open(DNS_LOG_FILE, mode="w", newline='') as file:
        writer = csv.writer(file)
        writer.writerow(["Timestamp", "Domain Name", "IP Address"])

class PacketDictionary:
    def __init__(self, output_file, timeout = UDP_TIMEOUT):
        self.data = dict()
        self.timers = dict()
        self.timeout = timeout
        self.lock = threading.Lock()
        self.output_file = output_file
    
    def set(self, key, value):
        with self.lock:
            if key in self.timers:
                self.timers[key].cancel()

            self.data[key] = value
            timer = threading.Timer(self.timeout, self.remove, args=[key])
            self.timers[key] = timer
            timer.start()
        
    def remove(self, key):
        with self.lock:
            response_data = self.data.pop(key)
            if(response_data[3] >= PACKET_SIZE_TRESHOLD):
                with open(self.output_file, mode="a", newline='') as file:
                    writer = csv.writer(file)
                    writer.writerow([response_data[0], response_data[1], key[0], key[1], response_data[2], response_data[3]])

            timer = self.timers.pop(key, None)
            if timer:
                timer.cancel()

    def get(self, key):
        with self.lock:
            return self.data.get(key, None)

def packet_get_addr_data(packet):
    if packet.haslayer(IP):
        src = packet[IP].src
        dst = packet[IP].dst
    elif packet.haslayer(IPv6):
        src = packet[IPv6].src
        dst = packet[IPv6].dst
    else:
        src, dst = None, None
    return src, dst

seen_udp_packets = PacketDictionary(UDP_LOG_FILE)

def packet_callback(packet):
    if packet.haslayer(DNS):
        dns_layer = packet[DNS]
        if dns_layer.qr == 1:  # DNS Response
            if dns_layer.haslayer(DNSRR):
                for answer in dns_layer.an:
                    if answer.type == 1:  # A Record (IPv4 address)
                        domain_name = answer.rrname.decode()
                        ip_address = answer.rdata
                        tag_ip(ip_address, domain_name) 

    if packet.haslayer(UDP):
        src_ip, dst_ip = packet_get_addr_data(packet)
        if IGNORE_LOCAL_IPS and src_ip and src_ip.startswith("192"):
            return

        timestamp = packet.time
        dst_port = packet[UDP].dport
        key = (src_ip, dst_port)
        prev_data = seen_udp_packets.get(key)
        if prev_data:
            start_time, _, total_size, total_packets = prev_data
            seen_udp_packets.set(key, [start_time, timestamp, total_size + len(packet), total_packets + 1])
        else:
            seen_udp_packets.set(key, [timestamp, timestamp, len(packet), 1])

def intercept_traffic():
    print("Intercepting...")
    try:
        sniff(iface=INTERFACE_NAME, lfilter=lambda pkt: pkt[Ether].src != Ether().src, prn=packet_callback, store=False)
    except Exception as e:
        intercept_traffic()
    
if __name__ == "__main__":
    try:
        intercept_traffic()
    except Exception as e:
        print("Crashed, restarting")
        intercept_traffic()