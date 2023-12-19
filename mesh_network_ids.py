#!/usr/bin/env python3
import threading
import logging
import re
import signal
import sys
import pyshark
import time
from collections import defaultdict

# Global flag to control thread termination
terminate_threads = False

# Configuration
network_interface = "eth0"
log_file = 'ids.log'
SYN_THRESHOLD = 5  # Number of SYN packets to trigger an alert
TIME_WINDOW = 15  # Time window in seconds to track SYN packets
port_scan_patterns = [
    re.compile(r"(?i)nmap"),
    re.compile(r"(?i)masscan"),
    # Add more patterns as needed
]

# Initialize a dictionary to track SYN packets per IP within a time window
syn_flood_tracker = defaultdict(lambda: defaultdict(lambda: {'count': 0, 'start_time': time.time()}))

# Create an empty dictionary to store detected port scan attempts
port_scan_attempts = {}
port_scan_lock = threading.Lock()

# Configure logging to a local file
logging.basicConfig(filename=log_file, level=logging.INFO, format='%(asctime)s - %(message)s')

# Function to remove ANSI escape codes
def remove_ansi_escape_sequences(text):
    ansi_escape_pattern = re.compile(r'\x1B[@-_][0-?]*[ -/]*[@-~]')
    return ansi_escape_pattern.sub('', text)

# Function to log SYN scans
def log_syn_scan(ip_address, port):
    logging.info(f"SYN scan detected from {ip_address} on port {port}")

# Function to log port scans based on payload patterns
def log_port_scan(ip_address, port):
    logging.info(f"Port scan detected from {ip_address} on port {port}")

# Configure a signal handler to gracefully exit the program
def signal_handler(sig, frame):
    global terminate_threads
    print("Terminating threads...")
    terminate_threads = True
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)

def analyze_packet(packet):
    formatted_packet = ""  # Declare variable before try block to avoid reference before assignment
    try:
        # Check if the packet has the IP layer
        if hasattr(packet, 'ip'):
            source_ip = packet.ip.src
            destination_ip = packet.ip.dst

            # Check if the packet is TCP
            if hasattr(packet, 'tcp'):
                tcp_layer = packet.tcp
                source_port = tcp_layer.srcport
                destination_port = tcp_layer.dstport

                # Check for port scan patterns in the payload
                if hasattr(tcp_layer, 'payload'):
                    packet_payload = tcp_layer.payload
                    if any(pattern.search(packet_payload) for pattern in port_scan_patterns):
                        log_port_scan(source_ip, source_port)

                # Check if the SYN flag is set for SYN scan detection
                if tcp_layer.flags_syn == '1' and tcp_layer.flags_ack == '0':
                    current_time = time.time()
                    syn_info = syn_flood_tracker[source_ip][destination_port]
                    syn_info['count'] += 1

                    if current_time - syn_info['start_time'] > TIME_WINDOW:
                        syn_info['count'] = 1
                        syn_info['start_time'] = current_time

                    if syn_info['count'] > SYN_THRESHOLD:
                        log_syn_scan(source_ip, destination_port)

                    formatted_packet = remove_ansi_escape_sequences(str(packet))
                    logging.info(f"SYN packet detected: {formatted_packet}")

            else:
                formatted_packet = remove_ansi_escape_sequences(str(packet))
                logging.info(f"Non-TCP packet or no payload: {formatted_packet}")

        else:
            formatted_packet = remove_ansi_escape_sequences(str(packet))
            logging.info(f"Non-IP packet: {formatted_packet}")

    except AttributeError as e:
        clean_error_message = remove_ansi_escape_sequences(str(e))
        logging.error(f"Attribute error: {clean_error_message} - Packet details: {formatted_packet}")
    except Exception as e:
        clean_error_message = remove_ansi_escape_sequences(str(e))
        logging.error(f"Exception occurred: {clean_error_message}")

def capture_traffic():
    capture = pyshark.LiveCapture(interface=network_interface)

    for packet in capture.sniff_continuously():
        if terminate_threads:
            break
        analyze_packet(packet)

# Start the pyshark capture in a separate thread
capture_thread = threading.Thread(target=capture_traffic)
capture_thread.start()

# Main loop for user interaction
try:
    print("IDS is running. Press Ctrl+C to exit.")
    while True:
        time.sleep(1)  # Sleep to reduce CPU usage, no need for active user input handling here.
except KeyboardInterrupt:
    # Handle any cleanup here
    terminate_threads = True

# Signal the threads to terminate
terminate_threads = True

# Join threads after breaking out of the loop
capture_thread.join()

print("All threads terminated.")
sys.exit(0)

