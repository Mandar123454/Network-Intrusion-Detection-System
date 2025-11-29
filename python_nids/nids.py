import logging
import time
import json
import os
from scapy.all import sniff, IP, TCP, UDP, ICMP

# Configuration
LOG_FILE = "logs/alerts.json"
os.makedirs("logs", exist_ok=True)

# Setup Logging
logging.basicConfig(filename='logs/nids.log', level=logging.INFO, format='%(asctime)s - %(message)s')

print("Starting Simple Python NIDS...")
print(f"Logging alerts to {LOG_FILE}")

# Define simple rules (in a real system, these would be loaded from a file)
RULES = [
    {"proto": "ICMP", "src_ip": "any", "dst_port": "any", "msg": "ICMP Ping Detected"},
    {"proto": "TCP", "src_ip": "any", "dst_port": 80, "msg": "HTTP Traffic Detected"},
    {"proto": "TCP", "src_ip": "any", "dst_port": 443, "msg": "HTTPS Traffic Detected"},
    {"proto": "TCP", "src_ip": "any", "dst_port": 22, "msg": "SSH Connection Attempt"},
    {"proto": "TCP", "src_ip": "any", "dst_port": 21, "msg": "FTP Connection Attempt"},
]

def take_response_action(alert):
    """
    Implement response mechanisms for detected intrusions.
    This could be blocking an IP, sending an email, or shutting down a service.
    """
    # Example: Simulate blocking the source IP
    print(f"    [RESPONSE] >>> Simulating Firewall Block for IP: {alert['src_ip']}")
    
    # Real Windows Firewall Block Command (Commented out for safety)
    # os.system(f'netsh advfirewall firewall add rule name="Block {alert["src_ip"]}" dir=in action=block remoteip={alert["src_ip"]}')

def log_alert(alert):
    """Log alert to JSON file and Console"""
    print(f"[ALERT] {alert['timestamp']} - {alert['msg']} - Src: {alert['src_ip']} -> Dst: {alert['dst_ip']}")
    
    # Trigger Response Mechanism
    take_response_action(alert)
    
    # Append to JSON log file
    try:
        with open(LOG_FILE, "a") as f:
            f.write(json.dumps(alert) + "\n")
    except Exception as e:
        print(f"Error writing to log: {e}")

def check_rules(packet):
    """Check packet against defined rules"""
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        
        proto = None
        dst_port = None

        if TCP in packet:
            proto = "TCP"
            dst_port = packet[TCP].dport
        elif UDP in packet:
            proto = "UDP"
            dst_port = packet[UDP].dport
        elif ICMP in packet:
            proto = "ICMP"
            dst_port = "any" # ICMP doesn't have ports in the same way

        if proto:
            for rule in RULES:
                if rule['proto'] == proto:
                    # Check Port Match
                    if rule['dst_port'] == "any" or rule['dst_port'] == dst_port:
                        # Check IP Match (Simplified)
                        if rule['src_ip'] == "any" or rule['src_ip'] == src_ip:
                            
                            alert = {
                                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                                "msg": rule['msg'],
                                "src_ip": src_ip,
                                "dst_ip": dst_ip,
                                "proto": proto,
                                "dst_port": dst_port
                            }
                            log_alert(alert)
                            return # Trigger only one rule per packet to avoid spam

def packet_callback(packet):
    try:
        check_rules(packet)
    except Exception as e:
        print(f"Error processing packet: {e}")

def start_sniffing(interface=None):
    print(f"Monitoring network traffic... (Press Ctrl+C to stop)")
    if interface:
        sniff(iface=interface, prn=packet_callback, store=0)
    else:
        sniff(prn=packet_callback, store=0)

if __name__ == "__main__":
    # You might need to specify the interface on Windows, e.g., "Ethernet" or "Wi-Fi"
    # Use scapy's show_interfaces() to find the name if needed.
    start_sniffing()
