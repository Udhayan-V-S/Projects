import os
import time
import threading
from scapy.all import sniff, IP, TCP, Raw

# SMTP ports
SMTP_PORTS = [25, 465, 587]

# Track suspicious activity
suspicious_senders = {}

# Deep packet inspection for SMTP analysis
def analyze_packet(packet):
 
    if packet.haslayer(TCP) and packet[TCP].dport in SMTP_PORTS:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst

        # Extract raw SMTP data safely
        raw_payload = packet[Raw].load.decode(errors="ignore") if packet.haslayer(Raw) else ""

        sender, recipient = "Unknown", "Unknown"
        if "MAIL FROM:" in raw_payload:
            sender = raw_payload.split("MAIL FROM:")[1].split("\r\n")[0].strip() if "MAIL FROM:" in raw_payload else "Unknown"
        if "RCPT TO:" in raw_payload:
            recipient = raw_payload.split("RCPT TO:")[1].split("\r\n")[0].strip() if "RCPT TO:" in raw_payload else "Unknown"

        print(f"[SMTP Activity] {src_ip} -> {dst_ip} | Sender: {sender} | Recipient: {recipient}")

        # Track suspicious activity
        if sender not in suspicious_senders:
            suspicious_senders[sender] = 1
        else:
            suspicious_senders[sender] += 1

        # Trigger alert if sender repeats suspiciously
        if suspicious_senders[sender] > 3:
            prompt_user_to_block(sender, src_ip)

def prompt_user_to_block(sender, src_ip):
    """Asks the user whether to block SMTP traffic."""
    print(f"\n[⚠ ALERT] Suspicious SMTP activity detected from {src_ip} (Sender: {sender})")
    choice = input("Do you want to block SMTP traffic for 1 minute? (yes/no): ").strip().lower()
    if choice == "yes":
        block_smtp_traffic()
    else:
        print("[INFO] SMTP traffic will not be blocked.")

# Blocks SMTP traffic for 1 minute
def block_smtp_traffic():
    print("[+] Blocking SMTP traffic...")
    
    # Save current iptables state before making changes
    os.system("iptables-save > /tmp/iptables_backup")

    # Block SMTP ports
    os.system("iptables -A OUTPUT -p tcp --dport 25 -j DROP")
    os.system("iptables -A OUTPUT -p tcp --dport 465 -j DROP")
    os.system("iptables -A OUTPUT -p tcp --dport 587 -j DROP")

    print("[INFO] SMTP traffic is blocked for 30 sec.")
    time.sleep(30)  # Wait for 30 sec

    # Restore previous firewall rules
    print("[+] Unblocking SMTP traffic...")
    os.system("iptables-restore < /tmp/iptables_backup")
    os.system("rm /tmp/iptables_backup")

# Monitors SMTP packets every 120 seconds
def monitor_smtp():
    while True:
        print("[*] Monitoring SMTP traffic for 120 seconds...")
        sniff(filter="tcp port 25 or tcp port 465 or tcp port 587", prn=analyze_packet, store=0, timeout=30)
        print("[INFO] Pausing scan... Will resume in 30 seconds.")
        time.sleep(120)  # Wait before next scan cycle

# Start monitoring in a separate thread
monitor_thread = threading.Thread(target=monitor_smtp, daemon=True)
monitor_thread.start()

# Keep the script running
while True:
    time.sleep(1)
