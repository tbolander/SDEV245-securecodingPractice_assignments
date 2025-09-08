# encrypt_decryptdemo using Caesar shift and RSA encryption with fixed prime numbers.

def caesar_encrypt(text, shift):
    result = ""
    for char in text:
        if char.isalpha():
            base = ord('A') if char.isupper() else ord('a')
            result += chr((ord(char) - base + shift) % 26 + base)
        else:
            result += char
    return result

def caesar_decrypt(text, shift):
    return caesar_encrypt(text, -shift)

def demo_rsakeys():
    # prime numbers!
    p, q = 89, 41
    n = p * q
    phi = (p-1) * (q-1)
    e = 17
    d = 5
    while (e * d) % phi != 1:
        d += 1
    return (e, n), (d, n)

def rsa_encrypt(msg, public):
    e, n = public
    return [pow(ord(c), e, n) for c in msg]

def rsa_decrypt(cipher, private):
    d, n = private
    return ''.join(chr(pow(c,d,n)) for c in cipher)

# main
if __name__ == "__main__":
    message = input("Enter a message to encrypt: ")
    print("og input:", message)
    print()

# symmetric
shift = 3
encrypted = caesar_encrypt(message, shift)
decrypted = caesar_decrypt(encrypted, shift)
print("Key shift:", shift)
print("(Caesar) Encrypted:", encrypted)
print("(Caesar) Decrypted:", decrypted)

# asymmetric 
public, private = demo_rsakeys()
encrypted_blocks = rsa_encrypt(message, public)
decrypted_message = rsa_decrypt(encrypted_blocks, private)
print("(RSA) Encrypted:", encrypted_blocks)
print("(RSA) Decrypted:", decrypted_message)
