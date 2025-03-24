import os
import subprocess
import time
import ctypes
from colorama import Fore, Style, init
from getpass import getpass
import sys
from rich import print as printc
# Importing the static and password check modules
from password_characteristics import check_character_occurences_in_password, check_password_characters_mixture
from password_characters_occurences import get_password_characters_occurences
from password_generator import password_generator
from password_entropy import get_entropy, password_level_sensibility
from have_i_been_pwned_check import check_haveibeenpwned_db

# Initialize colorama for colored output
init()

RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
CYAN = "\033[96m"
WHITE = "\033[97m"
RESET = "\033[0m"


def static_analysis():
    file_path = input(Fore.BLUE + "Enter file path to scan (or '0' to return to menu): " + Style.RESET_ALL)
    if file_path == '0':
        return
    
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


def full_system_scan():
    print(Fore.CYAN + "[INFO] Initiating a full system scan (this may take some time)..." + Style.RESET_ALL)
    print(Fore.YELLOW + "[NOTE] Press Ctrl+C at any time to return to menu" + Style.RESET_ALL)

    try:
        # Start a full system scan using Windows Defender
        result = subprocess.run(["powershell", "-Command", "Start-MpScan -ScanType FullScan"], capture_output=True, text=True)
        
        if result.returncode == 0:
            print(Fore.GREEN + "[SUCCESS] Full system scan started successfully!" + Style.RESET_ALL)
        else:
            print(Fore.RED + f"[ERROR] Failed to start full system scan: {result.stderr}" + Style.RESET_ALL)
        
        print(Fore.YELLOW + "[INFO] Waiting for scan results..." + Style.RESET_ALL)
        time.sleep(10)  # Allow some time for scanning to initiate

        while True:
            scan_status = subprocess.run(["powershell", "-Command", "Get-MpThreatDetection"],
                                         capture_output=True, text=True)
            
            if scan_status.stdout.strip():
                print(Fore.RED + "[ALERT] Threats detected!" + Style.RESET_ALL)
                
                threat_details = subprocess.run(["powershell", "-Command", "Get-MpThreat"],
                                                capture_output=True, text=True)
                
                file_name = "Unknown"
                file_path = "Unknown"
                
                for line in threat_details.stdout.split("\n"):
                    if "ThreatName" in line:
                        file_name = line.split(":")[-1].strip()
                    if "Path" in line:
                        file_path = line.split(":")[-1].strip()
                
                print(Fore.YELLOW + f"[INFO] Detected Threat: {file_name} at {file_path}" + Style.RESET_ALL)
                
                # Attempt to remove the threat
                remove_result = subprocess.run(["powershell", "-Command", "Remove-MpThreat"], capture_output=True)
                
                if remove_result.returncode == 0:
                    print(Fore.GREEN + "[SUCCESS] Threat removed successfully!" + Style.RESET_ALL)
                else:
                    print(Fore.RED + f"[ERROR] Failed to remove threat: {remove_result.stderr}" + Style.RESET_ALL)

            else:
                print(Fore.GREEN + "[SAFE] No threats detected." + Style.RESET_ALL)

            time.sleep(10)  # Check for threats every 10 seconds

    except KeyboardInterrupt:
        print(Fore.YELLOW + "[EXIT] Full system scan interrupted." + Style.RESET_ALL)
        return
    
    except Exception as e:
        print(Fore.RED + f"[ERROR] {e}" + Style.RESET_ALL)


def password_security_check():
    print(f"{BLUE}\n--------------------------------------------------\nPassword Security Check\n--------------------------------------------------{RESET}")
    user_password = getpass('Enter your password (or type "0" to return to menu): ')
    
    if user_password == '0':
        return
    
    printc("\n[cyan3 bold underline][*] Checking HaveIBeenPwned database[/cyan3 bold underline]")
    printc(check_haveibeenpwned_db(user_password))
    password_characters_occurences_dict, alphanumerical_characters_list = get_password_characters_occurences(user_password)
    check_password_characters_mixture(password_characters_occurences_dict, alphanumerical_characters_list)
    printc("[cyan3 bold underline][*] Password entropy[/cyan3 bold underline]")
    password_entropie = get_entropy(len(user_password), password_characters_occurences_dict)
    printc(password_level_sensibility(password_entropie))
    printc("\n[cyan3 bold underline][*] Password Generator[/cyan3 bold underline]")
    try:
        user_response = input('Do you wanna generate a password using our password generator [Yay/nay]: ')
        if user_response.lower() in ['', 'yay', 'yes', 'y', 'yeah', 'yep']:
            while True:
                password_length = input('Enter the password length (or "0" to cancel): ')
                if password_length == '0':
                    return
                if password_length.isdigit() and int(password_length) >= 20:
                    break
                printc('The password should have at least [red b]20[/red b] characters!')
            generated_password = password_generator(int(password_length))
            printc(f"[green1 b][+][/green1 b] The generated password was securely copied in your clipboard!")
            
            # Save the generated password to user_agents.db
            try:
                db_path = "db/user_agents.db"
                # Create directory if it doesn't exist
                os.makedirs(os.path.dirname(db_path), exist_ok=True)
                
                with open(db_path, "a") as f:
                    f.write(f"{generated_password}\n")
                printc(f"[green1 b][+][/green1 b] Password saved to database for future use in password cracking!")
            except Exception as e:
                printc(f"[red1 b][!][/red1 b] Failed to save password to database: {e}")
    except KeyboardInterrupt:
        return
    print("────────────────────────────────────────────────────────────────────────────")
    printc("[yellow1 b][!][/yellow1 b] Don't forget to [red1 b]CHANGE[/red1 b] your password [red1 b]ASAP[/red1 b] if it was considered insecure.")


def show_banner():
    """Display the AERIS Blue Team banner."""
    print(f"""{BLUE}
                 .--------.
                / .------. \\
               / /        \ \\
               | |        | |
              _| |________| |_
            .' |_|        |_| '.
            '._____ ____ _____.'
            |     .'_____'.    |
            '.__.'.'     '.'.__'
            '.__  | AERIS |  __'
            |   '.'.____.'.'   |
            '.____'.____.'____.'
            '.________________.'
            
        {RED}Author: Minhal | Version: 1.0{RESET}
            """)


def show_menu():
    """Display the Blue Team menu options."""
    print(f"{BLUE}╔══════════════════════════════════════════════════════╗")
    print(f"║               AERIS BLUE TEAM TOOLKIT                 ║")
    print(f"╚══════════════════════════════════════════════════════╝{RESET}")
    print(f"1- Static Analysis - Scan individual files")
    print(f"2- Dynamic Analysis - Run a complete system scan")
    print(f"3- Password Security Check - Evaluate password strength")
    print(f"0- Return to Main Menu")
    print(f"\n{BLUE}Enter your choice (0-3):{RESET}")


def main():
    """Main function for the Blue Team toolkit."""
    while True:
        # Check for admin privileges
        is_admin = ctypes.windll.shell32.IsUserAnAdmin()
        
        # Display banner and menu
        show_banner()
        
        if not is_admin:
            print(f"{RED}[ERROR] Please run this script as administrator!{RESET}")
            print(f"{YELLOW}Some features may not work correctly without admin privileges.{RESET}")
            print(f"{BLUE}Press Enter to continue anyway or type '0' to return to main menu: {RESET}")
            choice = input()
            if choice == '0':
                return True
        
        show_menu()
        choice = input().strip()
        
        if choice == '0':
            # Return to main menu
            print(f"{BLUE}Returning to main menu...{RESET}")
            return True
        
        elif choice == '1':
            # Static Analysis
            static_analysis()
            print("\nStatic analysis completed.")
            cont = input(f"{YELLOW}Press Enter to continue or '0' to return to main menu: {RESET}")
            if cont == '0':
                return True
            
        elif choice == '2':
            # Dynamic Analysis
            full_system_scan()
            print("\nDynamic analysis completed.")
            cont = input(f"{YELLOW}Press Enter to continue or '0' to return to main menu: {RESET}")
            if cont == '0':
                return True
            
        elif choice == '3':
            # Password Security Check
            password_security_check()
            print("\nPassword security check completed.")
            cont = input(f"{YELLOW}Press Enter to continue or '0' to return to main menu: {RESET}")
            if cont == '0':
                return True
            
        else:
            print(f"{RED}Invalid choice. Please select 0-3.{RESET}")
            time.sleep(1)
    
    return False


if __name__ == '__main__':
    main()