import os
import platform
import ctypes


blocked_ips = set()

def block_ip(ip):
    if ip in blocked_ips:
        return
    
  
    
    try:
        system = platform.system()
        
        
      #---------------------------------------------------------------------------------------------------------
                           #LINUX BLOCKING
      #---------------------------------------------------------------------------------------------------------
      
      
        
        
        if system == "Linux":
            if os.getuid() != 0:
                print("[-] Blocking failed: Root privileges required.")
                return
            cmd = f"iptables -A INPUT -s {ip} -j DROP"
            
      
      #---------------------------------------------------------------------------------------------------------
                           #WINDOWS BLOCKING
      #---------------------------------------------------------------------------------------------------------
         
            
        elif system =="Windows":
            if not ctypes.windll.shell32.IsUserAnAdmin():
                print("[-] Blocking failed:Administrator privileges required.")
                return
            cmd = f'netsh advfirewall firewall add rule name="IDPS_BLOCK_{ip}" dir=in action=block remoteip={ip}'
            
            
            
            
            
            
        else:
            print(f"[-] Blocking not implemented for {system}")
            return
        
        print(f"[+] Attempting to block {ip}...")
        result = os.system(cmd)
        
        if result == 0:
            blocked_ips.add(ip)
            print(f"[+] Successfully blocked {ip}")
            
        else:
            print(f"[-] Blocking failed for {ip} with error code {result}")
        
        
    except Exception as e:
        print(f"[-] Blocking failed: {e}")