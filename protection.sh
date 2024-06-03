#!/bin/bash

# use chmod +x network_check.sh
# Set the network to scan
network="192.168.1.0/24"  # Adjust this as needed

# File locations
normal_state_file="normal_state"
warnings_file="warnings"

# Function to check USB ports
check_usb_ports() {
    lsusb > current_usb_ports
}

# Function to perform nmap scan
perform_scan() {
    nmap -sn $network -oG -  # -sn for ping scan, -oG for grepable output
}

# Check if the normal state file exists
if [ ! -f "$normal_state_file" ]; then
    echo "Creating baseline state..."
    check_usb_ports
    perform_scan > "$normal_state_file"
    echo "Baseline state saved as $normal_state_file"
else
    echo "Baseline exists. Performing current state check..."
    check_usb_ports
    perform_scan > current_scan

    # Compare the new scan with the baseline
    diff_output=$(diff "$normal_state_file" current_scan)
    if [ -n "$diff_output" ]; then
        echo "WARNING: Differences detected!" | tee "$warnings_file"
        echo "$diff_output" | tee -a "$warnings_file"
    else
        echo "No differences detected."
    fi
fi

# Clean up current scan files
# rm current_scan current_usb_ports 2>/dev/null

echo "Scan complete. Any differences have been recorded in $warnings_file."
