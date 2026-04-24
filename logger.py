from datetime import datetime
from config import log_file

def log_attack(ip):
    
    time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log = f"[{time}] Blocked IP: {ip}\n"
    
    with open(log_file, "a") as f:
        f.write(log)
