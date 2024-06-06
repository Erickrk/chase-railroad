#!/bin/bash

# Set the network to scan
network="192.168.3.0/24"  # Adjust this as needed

# File locations
normal_state_file="normal_state"
normal_usb_state_file="normal_usb_state"
warnings_file="warnings"

# Function to check USB ports
check_usb_ports() {
    lsusb > current_usb_ports
}

# Function to perform nmap scan
perform_scan() {
    nmap -sn $network -oG -  # -sn for ping scan, -oG for grepable output
}

# Ensure the normal state files are created if they don't exist
if [ ! -f "$normal_state_file" ] || [ ! -f "$normal_usb_state_file" ]; then
    echo "Creating baseline state..."
    check_usb_ports
    cp current_usb_ports "$normal_usb_state_file"
    perform_scan | sed '1d;$d' > "$normal_state_file"
    echo "Baseline state saved as $normal_state_file and $normal_usb_state_file"
fi

# Loop to perform checks every 5 seconds
while true; do
    echo "Checking..."
    if [[ $1 == "-u" ]]; then
        check_usb_ports
        usb_diff_output=$(diff "$normal_usb_state_file" current_usb_ports)
        if [ -n "$usb_diff_output" ]; then
            echo "WARNING: Differences detected in USB ports!" | tee -a "$warnings_file"
            echo "$usb_diff_output" | tee -a "$warnings_file"
        else
            echo "No differences detected in USB ports."
        fi
    fi
    if [[ $1 == "-n" ]]; then
        perform_scan | sed '1d;$d' > current_scan
        diff_output=$(diff "$normal_state_file" current_scan)
        if [ -n "$diff_output" ]; then
            echo "WARNING: Differences detected in network!" | tee -a "$warnings_file"
            echo "$diff_output" | tee -a "$warnings_file"
        else
            echo "No differences detected in network."
        fi
    fi
    echo "Scan complete. Any differences have been recorded in $warnings_file."
    sleep 5
done