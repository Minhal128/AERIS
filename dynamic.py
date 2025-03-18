import os
import subprocess
import time
import ctypes
from colorama import Fore, Style, init

# Initialize colorama for colored output
init()

def real_time_scan():
    print(Fore.CYAN + "[INFO] Initiating real-time system scan..." + Style.RESET_ALL)
    
    while True:
        try:
            result = subprocess.run(["powershell", "-Command", "Get-MpThreatDetection"],
                                    capture_output=True, text=True)
            
            if "Threat" in result.stdout or "detected" in result.stdout:
                print(Fore.RED + "[ALERT] Malicious activity detected! Neutralizing..." + Style.RESET_ALL)
                subprocess.run(["powershell", "-Command", "Remove-MpThreat"], capture_output=True)
                print(Fore.GREEN + "[SUCCESS] Threat removed! System secure." + Style.RESET_ALL)
            else:
                print(Fore.GREEN + "[SAFE] No active threats detected." + Style.RESET_ALL)
        
            time.sleep(5)  # Adjust the scan interval as needed
        except KeyboardInterrupt:
            print(Fore.YELLOW + "[EXIT] Real-time monitoring stopped." + Style.RESET_ALL)
            break
        except Exception as e:
            print(Fore.RED + f"[ERROR] {e}" + Style.RESET_ALL)
            break

if __name__ == "__main__":
    if ctypes.windll.shell32.IsUserAnAdmin():
        real_time_scan()
    else:
        print(Fore.RED + "[ERROR] Please run this script as administrator!" + Style.RESET_ALL)
