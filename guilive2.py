from collections import Counter
import os
import time
import tkinter as tk
from tkinter import Label, Frame
import matplotlib.pyplot as plt
from PIL import Image, ImageTk
from io import BytesIO

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def read_conn_log(file_path):
    connections = []
    try:
        with open(file_path, 'r') as f:
            for line in f:
                if line.startswith("#") or line.strip() == "":
                    continue
                fields = line.strip().split("\t")
                connections.append(fields)
    except FileNotFoundError:
        print(f"File '{file_path}' not found.")
    return connections

def detect_suspicious_activity(connections):
    suspicious_activity = []
    for conn in connections:
        if len(conn) >= 16 and conn[4] == "tcp" and conn[15] == "S0":
            suspicious_activity.append(f"Failed connection attempt: {conn}")
    return suspicious_activity

def print_traffic_analysis(connections, prev_connections, prev_suspicious_activity):
    protocols = [conn[6] for conn in connections]
    top_talkers = Counter([conn[2] for conn in connections] + [conn[4] for conn in connections])
    suspicious_activity = detect_suspicious_activity(connections)

    if connections != prev_connections or suspicious_activity != prev_suspicious_activity:
        clear_screen()
        print("Total number of connections:", len(connections))
        print("Most common protocols:")
        for proto, count in Counter(protocols).most_common():
            print(f"{proto}: {count}")
        print("Top talkers:")
        for ip, count in top_talkers.most_common():
            print(f"{ip}: {count}")
        if suspicious_activity:
            print("Suspicious Activity:")
            for activity in suspicious_activity:
                print(activity)
        else:
            print("Suspicious Activity: NONE")
        print("Analyzing live traffic at:", time.ctime())
        print()
        return connections, suspicious_activity
    else:
        return prev_connections, prev_suspicious_activity

def update_gui():
    file_path = "/opt/zeek/logs/current/conn.log"
    connections = read_conn_log(file_path)
    suspicious_activity = detect_suspicious_activity(connections)
    display_traffic_analysis(connections, suspicious_activity)
    root.after(5000, update_gui)  # Update every 5 seconds

def display_traffic_analysis(connections, suspicious_activity):
    total_connections_label.config(text=f"Total connections: {len(connections)}")
    if suspicious_activity:
        suspicious_activity_label.config(text="Suspicious activity detected!", fg="red")
    else:
        suspicious_activity_label.config(text="No suspicious activity", fg="green")
    protocols = [conn[6] for conn in connections]
    protocol_counts = Counter(protocols)
    update_graph(protocol_counts)

def update_graph(protocol_counts):
    plt.clf()
    labels = list(protocol_counts.keys())
    counts = list(protocol_counts.values())
    plt.bar(labels, counts, color=['#1f77b4', '#ff7f0e', '#2ca02c'])
    plt.xlabel('Protocol')
    plt.ylabel('Count')
    plt.title('Protocol Distribution')
    plt.xticks(fontsize=10)
    plt.yticks(fontsize=10)
    plt.tight_layout()
    buf = BytesIO()
    plt.savefig(buf, format='png')
    buf.seek(0)
    img = Image.open(buf)
    img_tk = ImageTk.PhotoImage(img)
    graph_label.config(image=img_tk)
    graph_label.image = img_tk

root = tk.Tk()
root.title("Live Traffic Analysis")

main_frame = Frame(root, bg="#f0f0f0")
main_frame.pack(fill="both", expand=True, padx=20, pady=20)

title_label = Label(main_frame, text="Live Traffic Analysis", font=("Helvetica", 20), bg="#f0f0f0", fg="#333")
title_label.pack()

traffic_frame = Frame(main_frame, bg="#f0f0f0")
traffic_frame.pack(pady=10)

total_connections_label = Label(traffic_frame, text="Total connections: 0", font=("Helvetica", 12), bg="#f0f0f0", fg="#333")
total_connections_label.grid(row=0, column=0, padx=10)

suspicious_activity_label = Label(traffic_frame, text="No suspicious activity", font=("Helvetica", 12), bg="#f0f0f0", fg="green")
suspicious_activity_label.grid(row=0, column=1, padx=10)

graph_label = tk.Label(main_frame)
graph_label.pack()

update_gui()

root.mainloop()
