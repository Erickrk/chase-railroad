import subprocess
import logging

# Set up logging
logging.basicConfig(level=logging.INFO)

# Terminal 1: Continuously attempt a TCP handshake
tcp_handshake_script = """
import socket
from time import sleep
import logging

logging.basicConfig(level=logging.INFO)

def tcp_handshake():
    while True:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            s.connect(('target_ip', 80))  # Specify the target IP and port
            logging.info('TCP handshake successful')
        except socket.error as e:
            logging.error('Handshake failed: %s', e)
        finally:
            s.close()
        sleep(5)  # Wait for 5 seconds before retrying

tcp_handshake()
"""
# Run the TCP handshake in a new terminal
subprocess.Popen(['gnome-terminal', '--', 'bash', '-c', f"python3 -c '{tcp_handshake_script}'"])
logging.info("TCP handshake script is running in a new terminal.")

# Terminal 2: SSH and execute commands
ssh_commands = """
sshpass -p 'CHASE' ssh chase@192.168.5.1 'bash -s' << 'EOF'
scp ssh_and_move.py chase@192.168.5.1:/Downloads
python3 Downloads/ssh_and_move.py
EOF
"""
# Run the SSH commands in another new terminal
subprocess.Popen(['gnome-terminal', '--', 'bash', '-c', ssh_commands])
logging.info("SSH commands are running in another new terminal.")

logging.info("Commands are running in separate terminals.")
