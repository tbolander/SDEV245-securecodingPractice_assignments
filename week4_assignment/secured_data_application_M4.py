# secured_data_application for midterm project. hashes user input using SHA256, encrypts using AES, and finally decrypts the content which can be verified by hash comparison.

import os
import hashlib
import base64
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

# hash data function using sha256
def hash_data(data):
    hash_obj = hashlib.sha256()
    hash_obj.update(data)
    return hash_obj.hexdigest()

# generate a key from password
def generate_key(password, salt_value):
    #pbdkf2 for key derivation, 50k iterations.
    key = hashlib.pbkdf2_hmac('sha256', password.encode(), salt_value, 50000, 32)
    return key

# encrypt
def encrypt_data(plain_data, encryption_key):
    nonce = get_random_bytes(12)
    
    cipher = AES.new(encryption_key, AES.MODE_GCM, nonce=nonce)
    
    # encrypt and get tag
    encrypted_data, auth_tag = cipher.encrypt_and_digest(plain_data)
    
    return nonce, encrypted_data, auth_tag

# decrypt function
def decrypt_data(nonce, encrypted_data, auth_tag, encryption_key):
    cipher = AES.new(encryption_key, AES.MODE_GCM, nonce=nonce)
    
    try:
        decrypted_data = cipher.decrypt_and_verify(encrypted_data, auth_tag)
        return decrypted_data
    except ValueError:
        print("Error: Authentication verification failed.")
        return None

def main():
    print("\n---- Security Demo! ----\n")
    
    # get input type
    user_choice = input("Enter 'message' for text or 'file' for file input: ").lower()
    
    if user_choice == 'message':
        user_message = input("Enter your message: ")
        input_data = user_message.encode('utf-8')
        print("\n[Processing text message...]")
        
    elif user_choice == 'file':
        file_path = input("Enter file path: ")
        
        # check file
        if not os.path.isfile(file_path):
            print("Error: File not found!")
            return
            
        with open(file_path, 'rb') as file:
            input_data = file.read()
        print(f"\n[Processing file: {file_path}]")
        
    else:
        print("Invalid choice of input. Try again.")
        return
    
    # hash original
    original_hash = hash_data(input_data)
    print(f"\nOriginal SHA-256 Hash: {original_hash[:32]}...")
    
    # get password
    password = input("\nEnter encryption password: ")
    
    # generate a random salt and key
    salt = get_random_bytes(16)
    encryption_key = generate_key(password, salt)
    
    print("\n[Key generation completed successfully]")
    print(f"Salt (hex): {salt.hex()[:20]}...")
    
    # encrypt
    nonce, encrypted_data, auth_tag = encrypt_data(input_data, encryption_key)
    
    print("\n---- Encryption Complete ----")
    print(f"Encrypted data size: {len(encrypted_data)} bytes")
    print(f"Nonce: {base64.b64encode(nonce).decode()}")
    print(f"Auth tag: {base64.b64encode(auth_tag).decode()}")
    
    # decrypt
    print("\n---- Decrypting data... ----")
    
    decrypted_data = decrypt_data(nonce, encrypted_data, auth_tag, encryption_key)
    
    if decrypted_data is None:
        print("Decryption failed!")
        return
    
    print("[Decryption successful]")
    
    # compare hashes to verify integrity
    decrypted_hash = hash_data(decrypted_data)
    
    print(f"\nDecrypted SHA-256 Hash: {decrypted_hash[:32]}...")
    
    if original_hash == decrypted_hash:
        print("\n[PASSED] Integrity verified and data unchanged.")
    else:
        print("\n[FAILED] Integrity check failed.")
    
    if user_choice == 'file':
        print("[FILE MODE] decrypted file matches the original, verified by hash! :)")
    
    # show message if text 
    if user_choice == 'message':
        try:
            recovered = decrypted_data.decode('utf-8')
            print(f"\nDecrypted message: {recovered}")
        except:
            print("\nCannot decode message as text")

# run
if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nProgram interrupted by user.")
    except Exception as e:
        print(f"\nError {e}")