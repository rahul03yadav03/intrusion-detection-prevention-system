time_window = 20
thresold = 50
syn_thresold = 40
port_thresold=20
icmp_thresold=20




log_file = input("Enter log file name (default: logs.txt): ")

if not log_file:
    log_file = "logs.txt"




whitelist = [
    "127.",        
    "192.168.",    
    "10.",         
    "1.1.1.1",
    "8.8.8.8",
    "192.168.1.102"
]

ip_whitelist = input("Enter IP to add (or press Enter to skip): ")

if ip_whitelist:
    whitelist.append(ip_whitelist)