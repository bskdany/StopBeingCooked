import csv
import matplotlib.pyplot as plt
import matplotlib.dates as mdates
from datetime import datetime
from matplotlib.animation import FuncAnimation
import mplcursors  # for hover annotations

fig_udp, ax_udp = plt.subplots(figsize=(10, 6))

# Global variables
colors_pool = ['blue', 'green', 'red', 'cyan', 'magenta', 'yellow', 'orange']
ip_color_map_udp = {}
next_color_index_tcp = 0
next_color_index_udp = 0

csv_filename_udp = "traffic_logs/udp_aggregated.csv" 

def update_plot(frame, ax, csv_file, ip_color_map, next_color_index, protocol):
    ax.clear()
    start_times = []
    end_times = []
    packet_nums = []
    ips = []
    ports = []

    try:
        with open(csv_file, mode="r", newline='') as file:
            reader = csv.reader(file)
            next(reader)  # Skip header row
            for row in reader:
                start_time = float(row[0])
                end_time = float(row[1])
                source_ip = row[2]
                destination_port = row[3]
                packet_num = int(row[5])

                if packet_num < 100:
                    continue
                
                start_times.append(datetime.utcfromtimestamp(start_time))
                end_times.append(datetime.utcfromtimestamp(end_time))
                packet_nums.append(packet_num)
                ips.append(source_ip)
                ports.append(destination_port)

    except Exception as e:
        print(f"Error reading CSV: {e}")
        return

    if start_times:
        widths = [end_times[i] - start_times[i] for i in range(len(start_times))]
        
        bar_colors = []
        for ip in ips:
            if ip not in ip_color_map:
                ip_color_map[ip] = colors_pool[next_color_index % len(colors_pool)]
                next_color_index += 1
            bar_colors.append(ip_color_map[ip])
        
        bars = ax.bar(end_times, packet_nums, width=widths, color=bar_colors, align="edge")
        
        cursor = mplcursors.cursor(bars, hover=mplcursors.HoverMode.Transient)
        
        @cursor.connect("add")
        def on_add(sel):
            rect = sel.artist[sel.index]
            h = rect.get_height()
            port_value = ports[sel.index]
            ip_value = ips[sel.index]
            sel.annotation.set_text(f"IP: {ip_value}\nPort: {port_value}\nPackets: {int(h)}")
            x, y, w, bar_height = rect.get_bbox().bounds
            sel.annotation.xy = (x + w / 2, y + bar_height)

    ax.set_title(f"Real-Time {protocol.upper()} Packet Count Over Time")
    ax.set_xlabel("Timestamp")
    ax.set_ylabel("Total Packets")
    ax.xaxis.set_major_formatter(mdates.DateFormatter('%H:%M:%S'))
    plt.xticks(rotation=45)
    plt.tight_layout()

# def update_tcp(frame):
#     global next_color_index_tcp
#     update_plot(frame, ax_tcp, csv_filename_tcp, ip_color_map_tcp, next_color_index_tcp, "tcp")

def update_udp(frame):
    global next_color_index_udp
    update_plot(frame, ax_udp, csv_filename_udp, ip_color_map_udp, next_color_index_udp, "udp")

# Create separate animations for TCP and UDP
# ani_tcp = FuncAnimation(fig_tcp, update_tcp, interval=1000)
ani_udp = FuncAnimation(fig_udp, update_udp, interval=1000)

plt.show()
