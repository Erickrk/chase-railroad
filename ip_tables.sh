#!/bin/bash

# Default user and host IP
default_user="chase"
default_host="192.168.5.1"

# Usage: ./script.sh [attack|defend] [user@hostname]
if [[ $# -lt 1 ]]; then
    echo "Usage: $0 [attack|defend] [user@hostname]"
    echo "Defaulting to user@hostname: ${default_user}@${default_host}"
    host="${default_user}@${default_host}"
elif [[ $# -eq 1 ]]; then
    mode=$1
    host="${default_user}@${default_host}"
else
    mode=$1
    host=$2
fi

# SSH connection function
connect_ssh() {
    ssh -T $host << EOF
    $(declare -f $1)  # declare the function to use remotely
    $1  # call the function
EOF
}

# Attack function
attack() {
    echo "Initiating Attack..."
    # Drop all iptables rules
    sudo iptables -F
    sudo iptables -X
    sudo iptables -t nat -F
    sudo iptables -t nat -X
    sudo iptables -t mangle -F
    sudo iptables -t mangle -X
    # Stop the Zeek service
    sudo killall /opt/zeek/bin/zeek
    echo "Attack complete: iptables flushed and Zeek stopped."
}

# Defense function
defend() {
    echo "Initiating Defense..."
    # Save the current iptables state
    iptables-save > /tmp/iptables.current
    # Monitor iptables for changes
    while true; do
        sleep 10  # check every 10 seconds
        iptables-save > /tmp/iptables.new
        if ! diff /tmp/iptables.current /tmp/iptables.new > /dev/null; then
            echo "WARNING: iptables changed!"
            diff /tmp/iptables.current /tmp/iptables.new
            cp /tmp/iptables.new /tmp/iptables.current
        fi
    done
    # Implement defensive iptables rules
    # Example: Block a specific IP
    sudo iptables -A FORWARD -d 192.168.3.39/32 -i enp3s0 -p udp -j DROP
    sudo iptables -A FORWARD -d 192.168.3.39/32 -i enp3s0 -p tcp -j DROP
    sudo iptables -A FORWARD -d 192.168.3.18/32 -i enp3s0 -p tcp -j DROP
    sudo iptables -A FORWARD -d 192.168.3.18/32 -i enp3s0 -p udp -j DROP
    echo "Defense setup: iptables monitored and additional rules implemented."
}

# Decide the mode and execute
case "$mode" in
    attack)
        connect_ssh attack
        ;;
    defend)
        connect_ssh defend
        ;;
    *)
        echo "Invalid mode. Use 'attack' or 'defend'."
        exit 1
        ;;
esac
