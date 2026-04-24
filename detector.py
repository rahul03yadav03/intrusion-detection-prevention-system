from collections import defaultdict
import time
from config import time_window,thresold,whitelist, syn_thresold,port_thresold,icmp_thresold
from blocker import block_ip, blocked_ips
from logger import log_attack
from scapy.all import sniff, IP


ip_activity = defaultdict(list)
syn_activity = defaultdict(list)
port_activity = defaultdict(list)
icmp_activity = defaultdict(list)


def is_whitelisted(ip):
    for w in whitelist:
        if ip.startswith(w):
            return True
    return False

def detect_attack(packet):
    if not packet.haslayer("IP"):
        return 
        
    src_ip = packet["IP"].src 
    current_time = time.time()
        

        
    if is_whitelisted(src_ip):
        return
        
        
    #------------------------------------------------------------------------------ 
     #general flooding attack detection   
    #-------------------------------------------------------------------------------
    
    
    
    
        
    ip_activity[src_ip].append(current_time)
    
    
    ip_activity[src_ip] = [
        t for t in ip_activity[src_ip]
        
        if current_time-t <= time_window
    ]
    
    if len(ip_activity[src_ip]) > thresold:
        if src_ip not in blocked_ips:
            
            print(f"[!] ATTACK detected from {src_ip}")
            log_attack(src_ip)
            block_ip(src_ip)
        
        
        
    #------------------------------------------------------------------------------
        #SYN flooding attack detection
    #---------------------------------------------------------------------------
       
       
       
          
    if packet.haslayer("TCP") and packet["TCP"].flags == "S":
        syn_activity[src_ip].append(current_time)
        
        syn_activity[src_ip] =[
            t for t in syn_activity[src_ip]
            if current_time-t <= time_window
        ]
        
        if len(syn_activity[src_ip]) > syn_thresold:
            if src_ip not in blocked_ips:
              
                print(f"[!] SYN ATTACK detected from {src_ip}")
                log_attack(src_ip)
                block_ip(src_ip)
            
        
        
        
            
            
    #-------------------------------------------------------------------------------
           # Port scanning attack detection                                          
    #------------------------------------------------------------------------------- 
        
        
        
        
        
        
    if packet.haslayer("TCP"):
            dst_port = packet["TCP"].dport 
            
            port_activity[src_ip].append(dst_port)
            
            port_activity[src_ip] = port_activity[src_ip][-100:]

            unique_port = set(port_activity[src_ip])
            if len(unique_port) > port_thresold:
                if src_ip not in blocked_ips:
                    print(f"[!] PORT SCANNING detected from {src_ip}")
                    log_attack(src_ip)
                    block_ip(src_ip)   
                
                
                
    #-------------------------------------------------------------------------------
              #ICMP flooding attack detection
    #-------------------------------------------------------------------------------
    
    
    
    if packet.haslayer("ICMP"):
        icmp_activity[src_ip].append(current_time)
        
        icmp_activity[src_ip] = [
            t for t in icmp_activity[src_ip]
            if current_time-t <= time_window
        ]
        
        if len(icmp_activity[src_ip]) > icmp_thresold:
            if src_ip not in blocked_ips:
                print(f"[!] ICMP FLOODING detected from {src_ip}")
                log_attack(src_ip)
                block_ip(src_ip)
            
            
def alert(attack_type, src_ip):
    if src_ip in blocked_ips:
        return
    print(f"[!] {attack_type} detected from {src_ip}")
    log_attack(f"{attack_type}-{src_ip}")
    block_ip(src_ip)  
           