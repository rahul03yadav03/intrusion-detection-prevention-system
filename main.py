from scapy.all import sniff
from detector  import detect_attack

print("[*] Starting IDPS................")

def process_packet(packet):
    try:
        detect_attack(packet)
        
    except Exception as e:
        print(f"[-] Error processing packet: {e}")
    
try:
    sniff(prn= process_packet, store = False)
    
except KeyboardInterrupt:
    print("\n[*] Stopping IDPS...")