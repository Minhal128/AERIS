import os
import os.path
import subprocess
import sys
import ctypes
from colorama import Fore, Style, init

# Initialize colorama for colored output
init()

def scan_file_with_defender(file_path):
    if not os.path.exists(file_path):
        print(Fore.YELLOW + "[WARNING] File does not exist!" + Style.RESET_ALL)
        return
    
    print(Fore.CYAN + f"[INFO] Scanning file: {file_path}" + Style.RESET_ALL)
    
    try:
        result = subprocess.run(["powershell", "-Command", "Start-MpScan", "-ScanPath", f'"{file_path}"'],
                                capture_output=True, text=True)
        
        if "Threat" in result.stdout or "detected" in result.stdout:
            print(Fore.RED + "[ALERT] Malicious file detected! Deleting..." + Style.RESET_ALL)
            os.remove(file_path)
            print(Fore.GREEN + "[SUCCESS] File deleted successfully." + Style.RESET_ALL)
        else:
            print(Fore.GREEN + "[SAFE] No threats detected." + Style.RESET_ALL)
    except Exception as e:
        print(Fore.RED + f"[ERROR] {e}" + Style.RESET_ALL)

if __name__ == "__main__":
    if ctypes.windll.shell32.IsUserAnAdmin():
        file_path = input(Fore.BLUE + "Enter file path to scan: " + Style.RESET_ALL)
        scan_file_with_defender(file_path)
    else:
        print(Fore.RED + "[ERROR] Please run this script as administrator!" + Style.RESET_ALL)
