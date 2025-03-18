import random
import string
import pyperclip

def password_generator(length):
    """Generate a secure random password and copy to clipboard"""
    # Define character sets
    lowercase = string.ascii_lowercase
    uppercase = string.ascii_uppercase
    digits = string.digits
    special_chars = string.punctuation
    
    # Ensure at least one of each character type
    password = [
        random.choice(lowercase),
        random.choice(uppercase),
        random.choice(digits),
        random.choice(special_chars)
    ]
    
    # Fill the rest with random characters from all sets
    all_chars = lowercase + uppercase + digits + special_chars
    password.extend(random.choice(all_chars) for _ in range(length - 4))
    
    # Shuffle the password characters
    random.shuffle(password)
    
    # Convert list to string
    password = ''.join(password)
    
    # Copy to clipboard
    pyperclip.copy(password)
    
    print(f"Generated password: {password}")
    return password
