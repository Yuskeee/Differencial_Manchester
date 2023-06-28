import random
import math

def generate_keypair(p, q):
    # Step 1: Compute n = p * q
    n = p * q

    # Step 2: Compute Euler's totient function phi(n) = (p-1) * (q-1)
    phi = (p - 1) * (q - 1)

    # Step 3: Choose an integer e such that 1 < e < phi and gcd(e, phi) = 1
    e = random.randrange(1, phi)
    while math.gcd(e, phi) != 1:
        e = random.randrange(1, phi)

    # Step 4: Compute the modular multiplicative inverse d of e modulo phi
    d = pow(e, -1, phi)

    # Return the public and private keys
    # Public key: (e, n)
    # Private key: (d, n)
    return ((e, n), (d, n))

def rsa_encrypt(plain_text, public_key):
    # Unpack the public key
    e, n = public_key

    # Convert each character in the plain text to its corresponding ASCII value
    # Encrypt each ASCII value using the public key (e, n)
    encrypted_text = [pow(ord(char), e, n) for char in plain_text]

    # Return the encrypted text as a list of integers
    return encrypted_text

def rsa_decrypt(encrypted_text, private_key):
    # Unpack the private key
    d, n = private_key

    # Decrypt each encrypted integer using the private key (d, n)
    # Convert each decrypted integer to its corresponding ASCII character
    decrypted_text = ''.join([chr(pow(char, d, n)) for char in encrypted_text])

    # Return the decrypted text
    return decrypted_text

def differential_manchester_encode(data):
    encoded_data = []
    previous_bit_out = 1  # Start with a rising transition as the initial state

    for bit in data:
        previous_bit_out = previous_bit_out if bit == 1 else int(not previous_bit_out)
        encoded_data.append(previous_bit_out)
        encoded_data.append(int(not previous_bit_out))
        previous_bit_out = (int(not previous_bit_out))

    return encoded_data
    
def differential_manchester_decode(data):
    decoded_data = []
    previous_bit_out = 1  # Start with a rising transition as the initial state
    
    decoded_data.append(1 if previous_bit_out == data[0] else 0)

    i = 1
    while i < len(data) - 1:
        decoded_data.append(1 if data[i] == data[i+1] else 0)
        i += 2
    return decoded_data