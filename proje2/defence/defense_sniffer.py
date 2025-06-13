import os
import time
import json
from scapy.all import ARP, sniff, get_if_list

# Log dosyası yolu
LOG_PATH = "logs/sniff_alerts.jsonl"
ALERT_THRESHOLD = 2  # Aynı IP için kaç farklı MAC adresi tespit edilirse şüphelenilsin

# IP -> MAC eşlemesini tutar
arp_table = {}

# Terminal çıktısı 
def alert(msg):
    print(f"[!] {msg}")
def info(msg):
    print(f"[+] {msg}")

# Log dosyasına JSON satırı yaz
def log_event(event_type, ip, macs):
    os.makedirs("logs", exist_ok=True)
    log = {
        "time": time.strftime("%Y-%m-%d %H:%M:%S"),
        "type": event_type,
        "ip": ip,
        "macs": list(macs)
    }
    with open(LOG_PATH, "a", encoding="utf-8") as f:
        f.write(json.dumps(log) + "\n")

# Promiscuous mode kontrolü (Linux için geçerli)
def detect_promiscuous_mode():
    interfaces = get_if_list()
    suspicious = []
    for iface in interfaces:
        try:
            with open(f"/sys/class/net/{iface}/flags", "r") as f:
                flags = int(f.read().strip(), 16)
                if flags & 0x100:
                    suspicious.append(iface)
        except:
            continue
    return suspicious

# ARP spoofing kontrol fonksiyonu
def detect_arp(packet):
    if packet.haslayer(ARP) and packet[ARP].op == 2:
        ip = packet[ARP].psrc
        mac = packet[ARP].hwsrc

        if ip not in arp_table:
            arp_table[ip] = set()
        arp_table[ip].add(mac)

        if len(arp_table[ip]) >= ALERT_THRESHOLD:
            alert(f"ARP spoofing şüphesi! IP {ip} için birden fazla MAC adresi tespit edildi: {arp_table[ip]}")
            log_event("arp_spoof", ip, arp_table[ip])

# Ana izleme fonksiyonu
def monitor():
    info("SniffSense başlatıldı. Promiscuous mode ve ARP spoofing tespiti aktif...")

    # Promiscuous mode kontrolü
    promisc = detect_promiscuous_mode()
    if promisc:
        alert(f"Promiscuous mode açık: Şüpheli arayüz(ler): {promisc}")
        log_event("promiscuous_mode", "localhost", promisc)
    else:
        info("Promiscuous mod aktif değil.")

    # ARP paketlerini dinle
    sniff(filter="arp", prn=detect_arp, store=False)

# Uygulama doğrudan çalıştırılırsa
if __name__ == "__main__":
    monitor()
