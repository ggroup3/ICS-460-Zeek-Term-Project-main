import gzip
import os
import tkinter as tk
from tkinter import filedialog, Label, Entry, Button, Text, messagebox, Frame
from collections import Counter
import subprocess

# Function to get the list of available log directories
def get_log_directories():
    logs_dir = "/opt/zeek/logs/"
    log_directories = [f for f in os.listdir(logs_dir) if os.path.isdir(os.path.join(logs_dir, f))]
    return log_directories

# Placeholder function to opening input file dialog


def open_input_file_dialog(entry_widget):
    directory_path = filedialog.askdirectory(initialdir="/opt/zeek/logs/", title="Select directory")
    if directory_path:
        conn_files = []
        for dirpath, dirnames, filenames in os.walk(directory_path):
            for filename in filenames:
                if filename.startswith('conn.'):
                    conn_files.append(os.path.join(dirpath, filename))
        if conn_files:
            entry_widget.delete(0, tk.END)
            entry_widget.insert(tk.END, conn_files[0])  # Insert the first .conn file into the entry widget
        else:
            messagebox.showerror("Error", "No conn files found in the selected directory.")
    else:
        messagebox.showerror("Error", "No directory selected.")
# Placeholder function to  opening output file dialog
def open_output_file_dialog(output_entry):
    file_path = filedialog.asksaveasfilename(initialdir="/", title="Save file",
                                             filetypes=(("Log files", "*.log"), ("All files", "*.*")))
    output_entry.insert(tk.END, file_path)

# Function to reset GUI
def reset_gui(input_file_entry, output_text):
    input_file_entry.delete(0, tk.END)
    output_text.config(state='normal')
    output_text.delete('1.0', tk.END)
    output_text.config(state='disabled')
# Function to start live analysis
live_process = None
def start_live_analysis():
    global live_process
    live_process = subprocess.Popen(["python3", "guilive2.py"])

# Function to stop live analysis
def stop_live_analysis():
    global live_process
    if live_process:
        live_process.kill()
        live_process = None

# Functionality to process log file
processed_data = None

# Function to save processed data to file
def save_processed_data(output_file_path):
    global processed_data
    if processed_data and output_file_path:
        with open(output_file_path, 'w') as f:
            for conn in processed_data:
                f.write(' '.join(map(str, conn)) + '\n')
        messagebox.showinfo("Information", f"Processed log file saved to {output_file_path}")

# Modified function to open output file dialog
def open_output_file_dialog(output_entry):
    file_path = filedialog.asksaveasfilename(initialdir="/", title="Save file",
                                             filetypes=(("Log files", "*.log"), ("All files", "*.*")))
    output_entry.insert(tk.END, file_path)
    save_processed_data(file_path)  # Save processed data to selected file location
# Function to process log files and filter connections by protocol
def process_conn_file(file_path, protocol):
    connections = []
    protocols = []
    top_talkers = Counter()

    with gzip.open(file_path, 'rt') as f:
        for line in f:
            if line.startswith("#") or line.strip() == "":
                continue
            fields = line.strip().split("\t")
            src_ip, src_port, dest_ip, dest_port, proto = fields[2], fields[3], fields[4], fields[5], fields[6]
            connections.append((src_ip, src_port, dest_ip, dest_port, proto))
            protocols.append(proto)
            top_talkers.update([src_ip, dest_ip])

    # Filter connections by the specified protocol
    filtered_connections = [conn for conn in connections if conn[4] == protocol]

    return filtered_connections, protocols, top_talkers

# Function to process log file and display filtered connections
def process_log_file():
    global processed_data
    input_file_path = input_file_entry.get()
    if input_file_path:
        protocol = "tcp"  # Protocol to filter by (e.g., TCP)
        try:
            filtered_connections, _, _ = process_conn_file(input_file_path, protocol)
            if filtered_connections:
                # Store filtered connections in global variable
                processed_data = filtered_connections
                # Display filtered information in output_text widget
                output_text.config(state='normal')
                output_text.delete('1.0', tk.END)
                for conn in processed_data:
                    output_text.insert(tk.END, f"Source IP: {conn[0]}, Source Port: {conn[1]}, Destination IP: {conn[2]}, Destination Port: {conn[3]}, Protocol: {conn[4]}\n")
                output_text.config(state='disabled')
            else:
                messagebox.showinfo("Information", "No connections found for the specified protocol.")
        except Exception as e:
            messagebox.showerror("Error", f"Error processing log file: {str(e)}")
    else:
        messagebox.showerror("Error", "Please select an input log file before processing.")

# Functionality to display traffic summary
def display_traffic_summary():
    file_path = input_file_entry.get()
    if file_path:
        # Process the log file
        _, protocols, top_talkers = process_conn_file(file_path, protocol=None)
        # Display traffic summary
        summary_text = f"Total number of connections: {sum(top_talkers.values())}\n"
        summary_text += "Most common protocols:\n"
        for proto, count in Counter(protocols).most_common():
            summary_text += f"{proto}: {count}\n"
        summary_text += "Top talkers:\n"
        for ip, count in top_talkers.most_common():
            summary_text += f"{ip}: {count}\n"
        output_text.config(state='normal')
        output_text.delete('1.0', tk.END)
        output_text.insert(tk.END, summary_text)
        output_text.config(state='disabled')
    else:
        messagebox.showerror("Error", "Please select a log file before displaying the traffic summary.")

# GUI setup
root = tk.Tk()
root.title("Log File Analyzer")
# GUI components
frame = Frame(root)
frame.pack(padx=10, pady=10, expand=True, fill='both')

# Input file selection
input_file_label = Label(frame, text="Input File:")
input_file_label.grid(row=0, column=0, sticky="w")
input_file_entry = Entry(frame, width=50)
input_file_entry.grid(row=0, column=1, columnspan=3, sticky="ew")
input_file_button = Button(frame, text="Browse", command=lambda: open_input_file_dialog(input_file_entry))
input_file_button.grid(row=0, column=4)

# Output file selection
output_file_label = Label(frame, text="Output File (save as):")
output_file_label.grid(row=1, column=0, sticky="w")
output_file_entry = Entry(frame, width=50)
output_file_entry.grid(row=1, column=1, columnspan=3, sticky="ew")
output_file_button = Button(frame, text="Browse", command=lambda: open_output_file_dialog(output_file_entry))
output_file_button.grid(row=1, column=4)

# Output text area
output_label = Label(frame, text="Filtered Connections / Traffic Summary:")
output_label.grid(row=2, column=0, columnspan=5, sticky="w")
output_text = Text(frame, height=15, state='disabled')
output_text.grid(row=3, column=0, columnspan=5, sticky="ew")
# Buttons
process_button = Button(frame, text="Process Log File", command=process_log_file)
process_button.grid(row=4, column=0, columnspan=2, sticky="ew")

summary_button = Button(frame, text="Show Traffic Summary", command=display_traffic_summary)
summary_button.grid(row=4, column=2, columnspan=2, sticky="ew")

start_live_button = Button(frame, text="Start Live Analysis", command=start_live_analysis)
start_live_button.grid(row=5, column=0, columnspan=2, sticky="ew")

stop_live_button = Button(frame, text="Stop Live Analysis", command=stop_live_analysis)
stop_live_button.grid(row=5, column=2, columnspan=2, sticky="ew")

reset_button = Button(frame, text="Reset", command=lambda: reset_gui(input_file_entry, output_text))
reset_button.grid(row=5, column=4, columnspan=1, sticky="ew")

root.mainloop()
