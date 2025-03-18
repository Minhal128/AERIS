import hashlib
import requests
import argparse
import sys
import shlex  # Add this for command parsing

def banner():
    print("""
    =============================
        Python Hash Cracker
    =============================
    """)

def crack_hash(hash_type, hash_value, wordlist):
    try:
        print(f"[*] Attempting to crack {hash_type.upper()} hash: {hash_value}")
        print(f"[*] Using wordlist: {wordlist}")
        with open(wordlist, 'r', encoding='utf-8', errors='ignore') as file:
            for passwd in file:
                passwd = passwd.strip()
                if hash_type == "md5":
                    hashed_pass = hashlib.md5(passwd.encode()).hexdigest()
                elif hash_type == "sha1":
                    hashed_pass = hashlib.sha1(passwd.encode()).hexdigest()
                elif hash_type == "sha256":
                    hashed_pass = hashlib.sha256(passwd.encode()).hexdigest()
                elif hash_type == "sha512":
                    hashed_pass = hashlib.sha512(passwd.encode()).hexdigest()
                else:
                    print("[!] Unsupported hash type")
                    return

                if hashed_pass == hash_value:
                    print(f"[+] Password found: {passwd}")
                    return
            print("[-] Password not found in wordlist")
    except FileNotFoundError:
        print(f"[!] Wordlist file not found: {wordlist}")

def online_lookup(hash_value):
    print("[*] Searching online for hash...")
    url = f"http://hashtoolkit.com/reverse-hash?hash={hash_value}"
    response = requests.get(url)
    
    if response.status_code == 200:
        if hash_value in response.text:
            print("[+] Hash found online!")
        else:
            print("[-] Hash not found online.")
    else:
        print("[!] Failed to fetch data from HashToolKit.")

# New function that can accept command-line style arguments as a string
def hash_cracker_with_args(args_string=None):
    banner()
    parser = argparse.ArgumentParser(description="Hash Cracker Tool")
    parser.add_argument("-H", "--hash", required=True, help="Hash value to crack")
    parser.add_argument("-T", "--type", required=True, choices=["md5", "sha1", "sha256", "sha512"], help="Hash type")
    parser.add_argument("-W", "--wordlist", help="Path to wordlist file")
    parser.add_argument("-O", "--online", action='store_true', help="Perform online hash lookup")
    
    # Parse arguments from string if provided
    if args_string:
        try:
            args = parser.parse_args(shlex.split(args_string))
        except SystemExit:
            # Catch the exit that argparse calls on error
            return
    else:
        # Regular command-line parsing
        args = parser.parse_args()

    if args.wordlist:
        crack_hash(args.type, args.hash, args.wordlist)
    elif args.online:
        online_lookup(args.hash)
    else:
        print("[!] You must provide either a wordlist (-W) or enable online lookup (-O)")

# Original function for command-line use
def hash_cracker():
    hash_cracker_with_args()

# Call the function
if __name__ == "__main__":
    hash_cracker()