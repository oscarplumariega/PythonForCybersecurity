from scapy.all import *

def scan_port(ip, port):
    # Create IP and TCP layers
    ip_pkt = IP(dst=ip)
    tcp_pkt = TCP(dport=port, flags="S")

    pkt = ip_pkt / tcp_pkt
    resp = sr1(pkt, timeout=1, verbose=0)

    if resp is not None:
        if resp.haslayer(TCP):
            if resp.getlayer(TCP).flags == 0x12:  # SYN-ACK Control
                return True
            elif resp.getlayer(TCP).flags == 0x14:  # RST-ACK Control
                
                return False
    return False


target_ip = "10.0.2.12"
for port in range(20, 655000):
    status = scan_port(target_ip, port)
    if status:
        print(f"Port {port}: Open")
    else:
        continue