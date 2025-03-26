# AERIS: Purple Teaming Tool Guide

## What is AERIS?
AERIS is a cybersecurity tool that combines both offensive security testing (Red Team) and defensive security capabilities (Blue Team) in one application. This guide explains how the tool works and how to use it effectively.

---

## Components of AERIS
AERIS consists of three main Python files:

- **main.py** - The launcher for the entire toolkit
- **aerisb.py** - Blue Team (defensive) security tools
- **aerisr.py** - Red Team (offensive) security tools

---

## Module Overview

### Main Module (**main.py**)
This is the main launcher that provides:

- A colorful command-line interface
- Navigation menus to select tools
- Error handling and module loading

#### Imports:
- `os` and `sys`: For system interactions
- `time`: For delays and animations
- `importlib`: For dynamically loading the Red/Blue Team modules

---

### Blue Team Module (**aerisb.py**)
This module offers defensive security tools:

#### Features:
- **Static Analysis:** Scans individual files for malware using Windows Defender
  - Uses `subprocess` to run Windows Defender commands
- **Dynamic Analysis:** Performs a full system scan
  - Uses `ctypes` to check for administrator privileges
- **Password Security Check:** Evaluates password strength and security
  - Uses `getpass` for secure password input
  - Implements custom modules like `password_characteristics` and `have_i_been_pwned_check`
  - Uses `colorama` and `rich` for colorful terminal output

---

### Red Team Module (**aerisr.py**)
This module provides offensive security tools:

#### Features:
- **Brute Force:** Attempts to crack login credentials on websites
  - Uses `requests` for web interactions
  - Implements `BeautifulSoup` for parsing HTML
  - Uses `threading` for parallel password attempts
- **CipherLink:** Secure file transfer with encryption
  - Uses `tkinter` for the graphical interface
  - Implements `socket` for network communication
  - Uses `cryptography` libraries for encryption/decryption
- **Hash Cracker:** Tool to crack password hashes
  - Uses `hashlib` for hashing functions

---

## Understanding AERIS Import Statements

### Core Python Imports:
```python
import os
import sys
import time
import importlib
```
- **os:** Operating system interface
  - Used for clearing the screen (`os.system('cls')`)
  - Handles platform-specific operations
- **sys:** System-specific parameters and functions
  - Controls program exit (`sys.exit(0)`)
  - Handles stdout for animated text
  - Manages module reloading
- **time:** Time access and conversions
  - Creates delays between operations (`time.sleep()`)
  - Controls animation speed
- **importlib:** The implementation of the import statement
  - Dynamically loads Red and Blue Team modules
  - Reloads modules when needed (`importlib.reload()`)

---

### Defensive Security Imports (aerisb.py):
```python
import os
import subprocess
import time
import ctypes
from colorama import Fore, Style, init
from getpass import getpass
import sys
from rich import print as printc
```
- **subprocess:** Subprocess management
  - Executes Windows Defender commands (`Start-MpScan`)
  - Runs PowerShell commands from Python
- **ctypes:** Foreign function library
  - Checks if the program is running with admin privileges (`IsUserAnAdmin()`)
- **colorama:** Cross-platform colored terminal text
  - Provides colored output (`Fore.RED`, `Fore.GREEN`, etc.)
  - Initializes color support (`init()`)
- **getpass:** Secure password input
  - Gets passwords without displaying them on screen
- **rich:** Rich text and formatting in the terminal
  - Enhanced print functionality (`printc`)
  - Provides styling for console output

#### Password Security Modules:
```python
from password_characteristics import check_character_occurences_in_password, check_password_characters_mixture
from password_characters_occurences import get_password_characters_occurences
from password_generator import password_generator
from password_entropy import get_entropy, password_level_sensibility
from have_i_been_pwned_check import check_haveibeenpwned_db
```
- **password_characteristics:** Analyzes password composition
- **password_characters_occurences:** Checks character distribution
- **password_generator:** Creates secure passwords
- **password_entropy:** Calculates password strength
- **have_i_been_pwned_check:** Checks if the password has been leaked

---

### Offensive Security Imports (aerisr.py):
```python
from bs4 import BeautifulSoup
from tkinter import filedialog
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
```
- **BeautifulSoup:** HTML/XML parsing library
  - Extracts CSRF tokens from login pages
  - Parses HTML responses
- **tkinter:** Standard GUI library
  - Creates file selection dialogs
  - Builds the CipherLink GUI interface
- **cryptography modules:** Advanced cryptography library
  - `PBKDF2HMAC`: Key derivation function for secure passwords
  - `hashes`: Cryptographic hash functions
  - `padding`: Data padding for encryption
  - `Cipher, algorithms, modes`: Encryption/decryption operations
  - `default_backend`: Cryptographic backend implementation

#### Other Imports (Used within Functions):
```python
import requests
import socket
import struct
import threading
import re
```
- **requests:** HTTP library
  - Makes HTTP requests to target websites
  - Manages sessions for brute force attempts
- **socket:** Low-level networking interface
  - Creates network connections for file transfers
- **struct:** Handles binary data structures
  - Packs/unpacks binary data for network transmission
- **threading:** Thread-based parallelism
  - Runs password attempts in parallel
  - Prevents GUI freezing during file transfers
- **re:** Regular expression operations
  - Pattern matching for CSRF token extraction

---

## Conclusion
AERIS is a powerful cybersecurity tool that integrates both offensive and defensive security techniques. The combination of automated security analysis, encryption, brute force testing, and password security tools makes it a versatile resource for security professionals. Understanding the modules and their functionalities will allow users to effectively utilize AERIS for penetration testing, malware analysis, and security enhancements.

---

**Disclaimer:** This tool is intended for educational and ethical security research purposes only. Unauthorized use may violate legal and ethical guidelines.

