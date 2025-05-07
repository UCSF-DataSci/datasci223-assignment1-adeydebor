#!/usr/bin/env python3
# email_hasher.py
import sys
import hashlib

def hash_email(email):
    """
    Hash an email address using SHA-256 and return the hexadecimal digest.
    
    Args:
        email (str): The email address to hash
        
    Returns:
        str: The SHA-256 hash of the email in hexadecimal format
    """
    email_bytes = email.encode('utf-8')  
    sha256_hash = hashlib.sha256(email_bytes).hexdigest()  
    return sha256_hash 
    
def write_hash_to_file(hash_value, filename="hash.email"):  
    f = open(filename, "w")  
    f.write(hash_value)  
    f.close() 
    
def main():
    if len(sys.argv) != 2:  
        print("Usage: python email_hasher.py <email_address>")  
        sys.exit(1)  
    email = sys.argv[1]  
    hash_value = hash_email(email)  
    print(hash_value)  
    write_hash_to_file(hash_value)   

if __name__ == "__main__":
    main()
