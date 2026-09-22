import sys
import time
from scapy.all import IP, ICMP, send

def send_stealth_icmp(message: str, target_ip: str = "127.0.0.1"):
    for char in message:
        # Replicación de estructura ping real (8 bytes timestamp + 1 byte caracter + relleno)
        timestamp = int(time.time()).to_bytes(8, byteorder='little')
        padding = bytes(range(0x10, 0x38))
        payload = timestamp + char.encode('latin-1') + padding[1:]
       
        pkt = IP(dst=target_ip)/ICMP(type=8, code=0)/payload
        send(pkt, verbose=False)
        print("Sent 1 packets.")
        time.sleep(0.1)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Uso: sudo python3 pingv4.py \"<mensaje_cifrado>\" [IP]")
        sys.exit(1)
       
    msg = sys.argv[1]
    dest = sys.argv[2] if len(sys.argv) > 2 else "127.0.0.1"
    send_stealth_icmp(msg, dest)
