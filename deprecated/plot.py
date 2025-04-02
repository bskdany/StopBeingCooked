import csv
import matplotlib.pyplot as plt
from collections import defaultdict
import matplotlib.dates as mdates
from datetime import datetime
from deprecated.file_utils import get_latest_log

# Use latest file by default
csv_filename = get_latest_log() or "traffic_logs/default.csv"
# csv_filename = "traffic_logs/2025-02-17_aggregated.csv"

start_times = []
end_times = []
packet_sizes = []
packet_nums = []
protocols = []

# Read the CSV file
with open(csv_filename, mode="r", newline='') as file:
    reader = csv.reader(file)
    next(reader)  # Skip the header row
    
    for row in reader:
        start_time = float(row[0])  
        end_time = float(row[1])  
        src_ip = row[2]            
        dst_port = row[3]          
        packet_size = int(row[4])  
        packet_num = int(row[5])  
        
        start_times.append(datetime.utcfromtimestamp(start_time))
        end_times.append(datetime.utcfromtimestamp(end_time))  
        packet_nums.append(packet_num)
        packet_sizes.append(packet_size)


plt.figure(figsize=(10, 6))

widths = [end_times[i] - start_times[i] for i in range(len(start_times))]

print(max(packet_sizes))

plt.bar(end_times, packet_nums, label="Packets", width=widths, color="blue")

plt.title("Packet Sizes Over Time ")
plt.xlabel("Timestamp")
plt.ylabel("Packet Size (bytes)")
plt.legend()
plt.xticks(rotation=45)
plt.gca().xaxis.set_major_formatter(mdates.DateFormatter('%H:%M:%S'))  # Time format for the x-axis
plt.tight_layout()

plt.show()
