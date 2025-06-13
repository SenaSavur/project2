from scapy.all import sniff, IP, TCP, Raw
from datetime import datetime
import json
import os

# Log klasörü ve dosya
LOG_DIR = "logs"
LOG_FILE = os.path.join(LOG_DIR, "sniffer_logs.jsonl")

# Paket işlendiğinde çalışacak fonksiyon
def process_packet(packet):
    if packet.haslayer(IP) and packet.haslayer(TCP):
        ip_layer = packet[IP]
        tcp_layer = packet[TCP]

        log = {
            "time": datetime.now().isoformat(),
            "src": ip_layer.src,
            "dst": ip_layer.dst,
            "sport": tcp_layer.sport,
            "dport": tcp_layer.dport,
        }

        if packet.haslayer(Raw):
            payload = packet[Raw].load
            try:
                text = payload.decode(errors='ignore')
                lines = text.splitlines()

                # HTTP request ise analiz et
                if lines and ("HTTP" in lines[0] or lines[0].startswith("GET") or lines[0].startswith("POST")):
                    log["request_line"] = lines[0]
                    log["headers"] = {}

                    for line in lines[1:]:
                        if ": " in line:
                            k, v = line.split(": ", 1)
                            log["headers"][k] = v

                    if "POST" in lines[0]:
                        body_index = text.find("\r\n\r\n")
                        if body_index != -1:
                            body = text[body_index+4:]
                            log["post_body"] = body
                            if "username=" in body or "password=" in body:
                                log["contains_login_info"] = True

            except Exception as e:
                log["error"] = f"payload decode error: {str(e)}"

        # Dosyaya yaz
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(json.dumps(log) + "\n")

        # Terminalde göster
        print(log)

# Sniffer'ı başlat
def start_sniffer():
    print("Sniffer başlatıldı. TCP trafiği dinleniyor...\n")
    sniff(filter="tcp", iface="eth0", prn=process_packet, store=False)

# Ana fonksiyon
if __name__ == "__main__":
    start_sniffer()
