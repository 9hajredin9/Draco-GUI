import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from scapy.all import sniff, IP, TCP, UDP, ARP, ICMP, DNS, DHCP, Ether, get_if_list, rdpcap
import pandas as pd
import threading
import socket
import platform
from collections import defaultdict
import time

# Global variables
sniffing = False
packets_list = []
protocol_count = defaultdict(int)

# Global variable to control sniffing
sniffing_event = threading.Event()  # To control the sniffing process
sniffing_event.set()  # Start sniffing by default

# Function to capture packets
def packet_callback(packet):
    if packet.haslayer(Ether) and packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        src_mac = packet[Ether].src
        dst_mac = packet[Ether].dst
        timestamp = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())
        
        if packet.haslayer(TCP):
            protocol = "HTTP" if packet[TCP].dport == 80 or packet[TCP].sport == 80 else "HTTPS" if packet[TCP].dport == 443 or packet[TCP].sport == 443 else "TCP"
        elif packet.haslayer(UDP):
            protocol = "DNS" if packet[UDP].dport == 53 or packet[UDP].sport == 53 else "DHCP" if packet[UDP].dport == 67 or packet[UDP].sport == 68 else "UDP"
        elif packet.haslayer(ICMP):
            protocol = "ICMP"
        elif packet.haslayer(ARP):
            protocol = "ARP"
        else:
            protocol = "Other"
            
            # Default protocol for all IP packets that don't match the above
        
        # Add the packet to the list with correct protocol
        packets_list.append([src_ip, dst_ip, protocol, timestamp, len(packet), packet[Ether].src, packet[Ether].dst, packet.summary()])
        protocol_count[protocol] += 1
        
        # Insert packet info into treeview with packet row number
        tree.insert("", "end", values=(len(packets_list), src_ip, dst_ip, protocol, timestamp))
        
        # Update protocol statistics
        update_protocol_stats()

# Update protocol statistics
def update_protocol_stats():
    stat_text = f"Total Packets: {len(packets_list)}"
    total_packets_label.config(text=stat_text)

# Function to show graphical packet inspection
def show_packet_details(event):
    selected_item = tree.selection()
    if not selected_item:
        return

    packet_info = tree.item(selected_item, "values")
    if not packet_info:
        return

    src_ip = packet_info[1]
    dst_ip = packet_info[2]
    protocol = packet_info[3]
    
    # Find the matching packet
    selected_packet = None
    for packet in packets_list:
        if packet[0] == src_ip and packet[1] == dst_ip and packet[2] == protocol:
            selected_packet = packet
            break

    if not selected_packet:
        messagebox.showerror("Error", "Packet details not found.")
        return

    # Extract details
    src_mac = selected_packet[5]
    dst_mac = selected_packet[6]
    frame_content = selected_packet[7]
    timestamp = selected_packet[3]

    try:
        host_info = socket.gethostbyaddr(src_ip)
        hostname = host_info[0]
    except socket.herror:
        hostname = "Unknown"

    os_info = platform.system()

    # Create the pop-up window
    packet_window = tk.Toplevel(root)
    packet_window.title("Packet Details")
    packet_window.geometry("500x350")

    # Create the treeview for details
    packet_details_tree = ttk.Treeview(packet_window, columns=("Attribute", "Value"), show="headings")
    packet_details_tree.heading("Attribute", text="Attribute")
    packet_details_tree.heading("Value", text="Value")
    
    packet_details_tree.insert("", "end", values=("Source MAC", src_mac))
    packet_details_tree.insert("", "end", values=("Destination MAC", dst_mac))
    packet_details_tree.insert("", "end", values=("Protocol", protocol))
    packet_details_tree.insert("", "end", values=("Timestamp", timestamp))
    packet_details_tree.insert("", "end", values=("Hostname", hostname))
    packet_details_tree.insert("", "end", values=("System (OS)", os_info))
    packet_details_tree.insert("", "end", values=("Frame Content", frame_content))
    
    packet_details_tree.pack(expand=True, fill="both")

    # Footer label
    footer_label = tk.Label(packet_window, text="DRACO - Packet Inspection", font=("Arial", 10, "bold"), fg="black", bg="white")
    footer_label.pack(side="bottom", fill="x", pady=10)

def start_stop_sniffing():
    global sniffing
    if sniffing:
        # Stop sniffing
        sniffing = False
        start_stop_button.config(text="Start Sniffing", bg="green")
    else:
        # Start sniffing
        sniffing = True
        start_stop_button.config(text="Stop Sniffing", bg="red")
        interface = interface_combobox.get()
        traffic_filter = traffic_filter_combobox.get()  # Get selected traffic class filter
        
        if traffic_filter == "":
            traffic_filter = None  # Capture all traffic if no filter is selected
        
        # Start sniffing in a separate thread
        threading.Thread(target=sniff_packets, args=(interface, traffic_filter), daemon=True).start()

def sniff_packets(interface, traffic_filter):
    while sniffing:
        sniff(prn=packet_callback, store=False, iface=interface, filter=traffic_filter, timeout=1)


# Save packets to CSV
def save_csv():
    filename = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV files", "*.csv")])
    if filename:
        df = pd.DataFrame(packets_list, columns=["Source IP", "Destination IP", "Protocol", "Timestamp", "Frame Size", "Src MAC", "Dst MAC", "Frame Content"])
        df.to_csv(filename, index=False)
        messagebox.showinfo("Saved", "Packets saved successfully!")

# Open PCAP file
def open_pcap():
    file_path = filedialog.askopenfilename(filetypes=[("PCAP Files", "*.pcap")])
    if file_path:
        packets = rdpcap(file_path)
        for packet in packets:
            if packet.haslayer(Ether) and packet.haslayer(IP):
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
                timestamp = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())
                
                protocol = None
                if packet.haslayer(TCP):
                    protocol = "TCP"
                if packet.haslayer(UDP):
                    protocol = "UDP"
                if packet.haslayer(ICMP):
                    protocol = "ICMP"
                if packet.haslayer(ARP):
                    protocol = "ARP"
                if packet.haslayer(DNS):
                    protocol = "DNS"
                if packet.haslayer(DHCP):
                    protocol = "DHCP"
                if packet.haslayer(IP):
                    protocol = "IP"
                
                if not protocol:
                    protocol = "Other"
                
                # Add packet details
                packets_list.append([src_ip, dst_ip, protocol, timestamp, len(packet), packet[Ether].src, packet[Ether].dst, packet.summary()])
                tree.insert("", "end", values=(len(packets_list), src_ip, dst_ip, protocol, timestamp))
                protocol_count[protocol] += 1
        update_protocol_stats()

# Create the main window
root = tk.Tk()
root.title("D R A C O  !")
root.geometry("1000x800")
root.configure(bg="black")

# Cool title 
title_label = tk.Label(root, text="D     R     A     C     O     !", font=("Impact", 30), fg="white", bg="black")
title_label.pack(pady=10)

# "Made by: Hajredin Husejini"
made_by_label = tk.Label(root, text="Made by: Hajredin Husejini \n Gihub.com : 9hajredin9", font=("Arial", 12), fg="white", bg="black")
made_by_label.pack(pady=5)

# Traffic class filter
tk.Label(root, text="Traffic Class Filter:", font=("Arial", 12), fg="white", bg="black").pack()
traffic_filter_combobox = ttk.Combobox(root, font=("Arial", 12), values=["", "tcp", "udp", "icmp", "arp", "http", "https", "dhcp", "dns"])
traffic_filter_combobox.pack()

# Network interface selection
tk.Label(root, text="Select Network Interface:", font=("Arial", 12), fg="white", bg="black").pack()
interface_combobox = ttk.Combobox(root, font=("Arial", 12), values=get_if_list())
interface_combobox.pack()

# Buttons frame
button_frame = tk.Frame(root, bg="black")
button_frame.pack(pady=10)
start_stop_button = tk.Button(button_frame, text="Start Sniffing", command=start_stop_sniffing, bg="white", fg="black", font=("Arial", 12))
start_stop_button.grid(row=0, column=0, padx=5)
save_btn = tk.Button(button_frame, text="Save CSV", command=save_csv, bg="white", fg="black", font=("Arial", 12))
save_btn.grid(row=0, column=1, padx=5)
open_pcap_btn = tk.Button(button_frame, text="Open PCAP", command=open_pcap, bg="white", fg="black", font=("Arial", 12))
open_pcap_btn.grid(row=0, column=2, padx=5)

# Packet list table with row numbers
# Configure scrollbar

# Function to handle mouse wheel scrolling
tree_frame = tk.Frame(root)
tree_frame.pack(expand=True, fill="both", padx=10, pady=10)

# Create the treeview widget
tree = ttk.Treeview(tree_frame, columns=("Row", "Source IP", "Destination IP", "Protocol", "Timestamp"), show="headings")
tree.heading("Row", text="Row")
tree.heading("Source IP", text="Source IP")
tree.heading("Destination IP", text="Destination IP")
tree.heading("Protocol", text="Protocol")
tree.heading("Timestamp", text="Timestamp")
tree.pack(side="left", expand=True, fill="both", padx=10, pady=10)

# Create and configure the scrollbar
tree_scrollbar = tk.Scrollbar(tree_frame, orient="vertical", command=tree.yview)
tree_scrollbar.pack(side="right", fill="y")
tree.config(yscrollcommand=tree_scrollbar.set)

tree.bind("<Double-1>", show_packet_details)

# Function to handle mouse wheel scrolling
def on_tree_scroll(event):
    if event.delta:
        tree.yview_scroll(int(-1 * (event.delta / 120)), "units")  # Windows/macOS
    elif event.num == 4:
        tree.yview_scroll(-1, "units")  # Linux scroll up
    elif event.num == 5:
        tree.yview_scroll(1, "units")  # Linux scroll down

# Bind scroll wheel events
tree.bind("<MouseWheel>", on_tree_scroll)  # Windows/macOS
tree.bind("<Button-4>", on_tree_scroll)  # Linux scroll up
tree.bind("<Button-5>", on_tree_scroll)  # Linux scroll down



# Protocol stats label
total_packets_label = tk.Label(root, text="Total Packets: 0", font=("Arial", 12), fg="white", bg="black")
total_packets_label.pack(pady=10)

root.mainloop()
