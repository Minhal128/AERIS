# A purple teaming tool

## Blue Teaming Tools
- Static Analysis
- Dynamic Analysis
- Password Generator and Checher

## Red Teaming Tools
- Cipher Link
- Brute force
- Hash Cracker



"""
AERIS Toolkit Modules Overview
------------------------------
This file contains a comprehensive list of all modules used across the AERIS toolkit.
"""

# Standard Library Modules
STANDARD_MODULES = {
    "threading": "Used for multi-threading in brute force attacks and async operations",
    "time": "Used for timing operations and delays",
    "sys": "System-specific parameters and functions",
    "re": "Regular expression operations for CSRF token extraction",
    "os": "Operating system interfaces for file/directory operations",
    "socket": "Low-level networking interface for file transfer",
    "struct": "Functions to handle binary data in file transfers",
    "base64": "Base64 encoding/decoding",
    "subprocess": "Spawn new processes and connect to their input/output/error pipes",
    "ctypes": "Foreign function interface for calling C functions and using C data types",
    "getpass": "Secure password input from terminal",
    "hashlib": "Secure hash and message digest algorithms for hash cracking"
}

# Third-Party Modules
THIRD_PARTY_MODULES = {
    # Web & Networking
    "requests": "HTTP library for making web requests in brute force attacks",
    "bs4.BeautifulSoup": "HTML parsing library for web scraping and CSRF token extraction",
    
    # GUI & Interface
    "tkinter": "Standard GUI toolkit for file transfer interface",
    "tkinter.filedialog": "Dialog for selecting files in GUI",
    "colorama": "Cross-platform colored terminal output",
    "rich": "Rich text formatting in terminal",
    
    # Cryptography
    "cryptography.hazmat.primitives.kdf.pbkdf2.PBKDF2HMAC": "Key derivation function",
    "cryptography.hazmat.primitives.hashes": "Hash functions",
    "cryptography.hazmat.primitives.padding": "Padding for cryptographic operations",
    "cryptography.hazmat.primitives.ciphers.Cipher": "Symmetric encryption ciphers",
    "cryptography.hazmat.primitives.ciphers.algorithms": "Cipher algorithms",
    "cryptography.hazmat.primitives.ciphers.modes": "Cipher modes",
    "cryptography.hazmat.backends": "Backend implementations for cryptography"
}

# Custom Modules
CUSTOM_MODULES = {
    "password_characteristics": "Checks characteristics of passwords",
    "password_characters_occurences": "Analyzes character occurrences in passwords",
    "password_generator": "Generates secure passwords",
    "password_entropy": "Calculates password entropy",
    "have_i_been_pwned_check": "Checks passwords against HaveIBeenPwned database"
}

# Module Dependencies by AERIS Component
COMPONENT_DEPENDENCIES = {
    "Brute Force": [
        "threading", "requests", "time", "sys", "re", "bs4.BeautifulSoup", "os"
    ],
    
    "CipherLink (Secure File Transfer)": [
        "tkinter", "tkinter.filedialog", "socket", "cryptography.*", 
        "base64", "os", "struct", "threading"
    ],
    
    "Hash Cracker": [
        "hashlib", "requests", "os", "sys"
    ],
    
    "Password Security": [
        "getpass", "rich", "sys", "os", "password_characteristics", 
        "password_characters_occurences", "password_generator", 
        "password_entropy", "have_i_been_pwned_check"
    ],
    
    "System Security": [
        "os", "subprocess", "time", "ctypes", "colorama"
    ]
}

# Required pip installations
PIP_REQUIREMENTS = """
# Standard requirements for AERIS toolkit
requests>=2.25.1
beautifulsoup4>=4.9.3
cryptography>=3.4.6
colorama>=0.4.4
rich>=10.0.0
"""

if __name__ == "__main__":
    print("AERIS Toolkit Modules Overview")
    print("==============================")
    
    print("\nStandard Library Modules:")
    for module, description in STANDARD_MODULES.items():
        print(f"- {module}: {description}")
    
    print("\nThird-Party Modules:")
    for module, description in THIRD_PARTY_MODULES.items():
        print(f"- {module}: {description}")
    
    print("\nCustom Modules:")
    for module, description in CUSTOM_MODULES.items():
        print(f"- {module}: {description}")
    
    print("\nTo install required third-party modules:")
    print("pip install -r requirements.txt")
    
    # Generate requirements.txt
    with open("requirements.txt", "w") as f:
        f.write(PIP_REQUIREMENTS)
    
    print("\nGenerated requirements.txt file.")