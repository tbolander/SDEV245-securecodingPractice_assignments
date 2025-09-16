# secureEncrypt_demo using SHA-256 hash, caesar cipher example and digital signature with toy RSA.

import hashlib
import os

# create SHA-256 hash
def hash_text(text):
    return hashlib.sha256(text.encode()).hexdigest()

def hash_file(filename):
    h = hashlib.sha256()
    with open(filename, 'rb') as f:
        h.update(f.read())
    return h.hexdigest()

# caesar cipher (encryption/decryption)
def caesar_cipher(text, shift, decrypt=False):
    if decrypt:
        shift = -shift
    result = ""
    for char in text:
        if char.isalpha():
            base = ord('A') if char.isupper() else ord('a')
            result += chr((ord(char) - base + shift) % 26 + base)
        else:
            result += char
    return result

# RSA keys (previous weeks caesar program, uses tiny prime values for demo.)
def make_keys():
    # tiny primes! Only an example for week 3 submission.
    p, q = 89, 41
    n = p * q
    e = 17
    phi = (p-1) * (q-1)
    d = pow(e, -1, phi)
    return (e, n), (d, n)

# RSA sign / verify
def sign(message, private_key):
    d, n = private_key
    hash_int = int(hash_text(message), 16) % n
    return pow(hash_int, d, n)

def verify(message, signature, public_key):
    e, n = public_key
    hash_int = int(hash_text(message), 16) % n
    return pow(signature, e, n) == hash_int

# demo!
if __name__ == "__main__":
    msg = input("Message: ")
    
print("\nSHA-256: ")
print("Text hash:", hash_text(msg))
# file to hash? if no, "no", "skip" will skip this step.
file = input("File to hash?: ")
if file.lower() not in ("", "no", "skip"):
    if os.path.exists(file):
        print("File hash:", hash_file(file))
    else:
        print("File not found:", file)
else:
    print("Skipping file hash...")

print("\nCaesar Cipher: ")
encrypted = caesar_cipher(msg, 3)
decrypted = caesar_cipher(encrypted, 3, decrypt=True)
print(f"Original: {msg}")
print(f"Encrypted: {encrypted}")  
print(f"Decrypted: {decrypted}")
    
print("\nDigital Signature: ")
public, private = make_keys()
signature = sign(msg, private)
valid = verify(msg, signature, public)
print("Public key:", public)
print("Private key:", private)
print(f"Signature: {signature}")
print(f"Valid: {valid}")
