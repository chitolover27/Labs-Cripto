from scapy.all import rdpcap, ICMP

GREEN = "\033[92m"
RESET = "\033[0m"

SPANISH_WORDS = ["que", "de", "en", " y ", " la ", " el ", "seguridad", "criptografia", "redes"]

def decrypt_cesar(text: str, shift: int) -> str:
    res = []
    for char in text:
        if 'a' <= char <= 'z':
            res.append(chr((ord(char) - ord('a') - shift) % 26 + ord('a')))
        elif 'A' <= char <= 'Z':
            res.append(chr((ord(char) - ord('A') - shift) % 26 + ord('A')))
        else:
            res.append(char)
    return "".join(res)

def extract_payload(pcap_file: str) -> str:
    packets = rdpcap(pcap_file)
    extracted = []
    for pkt in packets:
        if pkt.haslayer(ICMP) and pkt[ICMP].type == 8:  # Echo Request
            payload = bytes(pkt[ICMP].payload)
            if len(payload) >= 9:
                extracted.append(chr(payload[8]))
    return "".join(extracted)

def main():
    try:
        raw_msg = extract_payload("cesar.pcapng")
    except Exception as e:
        print(f"Error al leer el archivo PCAP: {e}")
        return

    best_shift = 0
    max_score = -1
    results = []

    for shift in range(26):
        candidate = decrypt_cesar(raw_msg, shift)
        score = sum(1 for word in SPANISH_WORDS if word in candidate.lower())
        results.append((shift, candidate))
        if score > max_score:
            max_score = score
            best_shift = shift

    for shift, text in results:
        if shift == best_shift:
            print(f"{GREEN}{shift:<3} {text}{RESET}")
        else:
            print(f"{shift:<3} {text}")

if __name__ == "__main__":
    main()
