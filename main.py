import os
import sys
import time
import importlib

# ANSI color codes
PURPLE = "\033[95m"
BLUE = "\033[94m"
CYAN = "\033[96m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
RESET = "\033[0m"
BOLD = "\033[1m"
UNDERLINE = "\033[4m"

def clear_screen():
    """Clear the terminal screen."""
    os.system('cls' if os.name == 'nt' else 'clear')

def print_banner():
    """Display the AERIS banner."""
    clear_screen()
    banner = f"""
{PURPLE}{BOLD}
    ▄▄▄       ▓█████  ██▀███   ██▓  ██████ 
   ▒████▄     ▓█   ▀ ▓██ ▒ ██▒▓██▒▒██    ▒ 
   ▒██  ▀█▄   ▒███   ▓██ ░▄█ ▒▒██▒░ ▓██▄   
   ░██▄▄▄▄██  ▒▓█  ▄ ▒██▀▀█▄  ░██░  ▒   ██▒
    ▓█   ▓██▒▒░▒████▒░██▓ ▒██▒░██░▒██████▒▒
    ▒▒   ▓▒█░░░░ ▒░ ░░ ▒▓ ░▒▓░░▓  ▒ ▒▓▒ ▒ ░
     ▒   ▒▒ ░ ░ ░  ░  ░▒ ░ ▒░ ▒ ░░ ░▒  ░ ░
     ░   ▒      ░     ░░   ░  ▒ ░░  ░  ░  
         ░  ░   ░  ░   ░      ░        ░  
{RESET}
{PURPLE}{BOLD}┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓{RESET}
{PURPLE}{BOLD}┃                      {RESET}{CYAN}AERIS - Purple Teaming Tool{RESET}{PURPLE}{BOLD}                      ┃{RESET}
{PURPLE}{BOLD}┃                                                                      ┃{RESET}
{PURPLE}{BOLD}┃{RESET} {YELLOW}Author: Minhal{RESET}                                  {CYAN}Version: 1.0{RESET} {PURPLE}{BOLD}┃{RESET}
{PURPLE}{BOLD}┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛{RESET}
"""
    print(banner)

def animate_text(text, delay=0.03):
    """Animate text printing character by character."""
    for char in text:
        sys.stdout.write(char)
        sys.stdout.flush()
        time.sleep(delay)
    print()

def display_menu():
    """Display the main menu options."""
    animate_text(f"{CYAN}{BOLD}Select your operation mode:{RESET}")
    print(f"\n{RED}[1]{RESET} {BOLD}Red Team{RESET} - Offensive Security Tools")
    print(f"   ├─ Brute Force")
    print(f"   ├─ CipherLink")
    print(f"   └─ Hash Cracker")
    print()
    print(f"{BLUE}[2]{RESET} {BOLD}Blue Team{RESET} - Defensive Security Tools")
    print(f"   ├─ Static Analysis")
    print(f"   ├─ Dynamic Analysis")
    print(f"   └─ Password Security Check")
    print()
    print(f"{YELLOW}[3]{RESET} {BOLD}Exit{RESET}")
    print(f"\n{PURPLE}{'─' * 72}{RESET}")

def run_tool(module_name):
    """Run the selected tool module and return to main menu when done."""
    try:
        # Import the module dynamically
        module = importlib.import_module(module_name)
        
        # Call the main function of the module
        if hasattr(module, 'main'):
            module.main()
        else:
            print(f"\n{RED}Error: {module_name} does not have a main() function.{RESET}")
    except ImportError:
        print(f"\n{RED}Error: Could not find module {module_name}.{RESET}")
    except Exception as e:
        print(f"\n{RED}Error running {module_name}: {str(e)}{RESET}")
    
    # Always return to main menu after tool execution
    input(f"\n{YELLOW}Press Enter to return to the main menu...{RESET}")

# Updates to the run_tool function

def main():
    """Main function to run the AERIS toolkit launcher."""
    while True:
        print_banner()
        display_menu()
        
        choice = input(f"\n{CYAN}Enter your choice (1-3): {RESET}")
        
        if choice == '1':
            # Run Red Team Tool (aerisr.py)
            animate_text(f"\n{RED}Starting Red Team Tools...{RESET}")
            time.sleep(1)
            
            # Import and run the red team module directly
            try:
                # Force reload the module in case it was modified
                if 'aerisr' in sys.modules:
                    importlib.reload(sys.modules['aerisr'])
                else:
                    import aerisr
                
                # If main returns True, it means user wants to return to main menu
                sys.modules['aerisr'].main()
                # No need for additional input prompt since aerisr handles return to menu
            except ImportError as e:
                print(f"\n{RED}Error: Could not import aerisr module. Make sure aerisr.py exists.{RESET}")
                print(f"{RED}Details: {str(e)}{RESET}")
                input(f"\n{YELLOW}Press Enter to return to the main menu...{RESET}")
            except SyntaxError as e:
                print(f"\n{RED}Syntax error in aerisr.py: {str(e)}{RESET}")
                print(f"{RED}Please fix the syntax error and try again.{RESET}")
                input(f"\n{YELLOW}Press Enter to return to the main menu...{RESET}")
            except Exception as e:
                print(f"\n{RED}Error: {str(e)}{RESET}")
                import traceback
                traceback.print_exc()
                input(f"\n{YELLOW}Press Enter to return to the main menu...{RESET}")
                
        elif choice == '2':
            # Run Blue Team Tool (aerisb.py)
            animate_text(f"\n{BLUE}Starting Blue Team Tools...{RESET}")
            time.sleep(1)
            
            # Import and run the blue team module directly
            try:
                # Force reload the module in case it was modified
                if 'aerisb' in sys.modules:
                    importlib.reload(sys.modules['aerisb'])
                else:
                    import aerisb
                
                # If main returns True, it means user wants to return to main menu
                sys.modules['aerisb'].main()
                # No need for additional input prompt since aerisb handles return to menu
            except ImportError as e:
                print(f"\n{RED}Error: Could not import aerisb module. Make sure aerisb.py exists.{RESET}")
                print(f"{RED}Details: {str(e)}{RESET}")
                input(f"\n{YELLOW}Press Enter to return to the main menu...{RESET}")
            except SyntaxError as e:
                print(f"\n{RED}Syntax error in aerisb.py: {str(e)}{RESET}")
                print(f"{RED}Please fix the syntax error and try again.{RESET}")
                input(f"\n{YELLOW}Press Enter to return to the main menu...{RESET}")
            except Exception as e:
                print(f"\n{RED}Error: {str(e)}{RESET}")
                import traceback
                traceback.print_exc()
                input(f"\n{YELLOW}Press Enter to return to the main menu...{RESET}")
        
        elif choice == '3':
            # Exit
            animate_text(f"\n{GREEN}Thank you for using AERIS. Goodbye!{RESET}")
            time.sleep(1)
            break
        else:
            print(f"\n{RED}Invalid choice. Please enter 1, 2, or 3.{RESET}")
            time.sleep(2)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n\n{YELLOW}AERIS terminated. Goodbye!{RESET}")
        sys.exit(0)