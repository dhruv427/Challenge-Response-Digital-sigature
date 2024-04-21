import socket
import hashlib
import json
import random

def gcd(a, b):
    while b != 0:
        a, b = b, a % b
    return a

def multiplicative_inverse(e, phi):
    d = 0
    x1 = 0
    x2 = 1
    y1 = 1
    temp_phi = phi

    while e > 0:
        temp1 = temp_phi//e
        temp2 = temp_phi - temp1 * e
        temp_phi = e
        e = temp2

        x = x2 - temp1 * x1
        y = d - temp1 * y1

        x2 = x1
        x1 = x
        d = y1
        y1 = y

    if temp_phi == 1:
        return d + phi


'''
Tests to see if a number is prime.
'''


def is_prime(num):
    if num == 2:
        return True
    if num < 2 or num % 2 == 0:
        return False
    for n in range(3, int(num**0.5)+2, 2):
        if num % n == 0:
            return False
    return True


def generate_key_pair(p, q):
    if not (is_prime(p) and is_prime(q)):
        raise ValueError('Both numbers must be prime.')
    elif p == q:
        raise ValueError('p and q cannot be equal')
    # n = pq
    n = p * q

    # Phi is the totient of n
    phi = (p-1) * (q-1)

    # Choose an integer e such that e and phi(n) are coprime
    e = random.randrange(1, phi)

    # Use Euclid's Algorithm to verify that e and phi(n) are coprime
    g = gcd(e, phi)
    while g != 1:
        e = random.randrange(1, phi)
        g = gcd(e, phi)

    # Use Extended Euclid's Algorithm to generate the private key
    d = multiplicative_inverse(e, phi)

    # Return public and private key_pair
    # Public key is (e, n) and private key is (d, n)
    return ((e, n), (d, n))


def encrypt(pk, plaintext):
    # Unpack the key into it's components
    key, n = pk
    # Convert each letter in the plaintext to numbers based on the character using a^b mod m
    cipher = [pow(ord(char), key, n) for char in plaintext]
    # Return the array of bytes
    return cipher


def decrypt(pk, ciphertext):
    # Unpack the key into its components
    key, n = pk
    # Generate the plaintext based on the ciphertext and key using a^b mod m
    aux = [str(pow(char, key, n)) for char in ciphertext]
    # Return the array of bytes as a string
    plain = [chr(int(char2)) for char2 in aux]
    return ''.join(plain)


def SHA(str):
  result = hashlib.sha256(str.encode())

# printing the equivalent hexadecimal value.
  # print("The hexadecimal equivalent of SHA256 is : ")
  return result.hexdigest()
  # f6071725e7ddeb434fb6b32b8ec4a2b14dd7db0d785347b2fb48f9975126178f
  # print ("\r")


# Define server address and port
SERVER_HOST = '127.0.0.1'
SERVER_PORT = 12345

# Create a socket object
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Connect to the server
client_socket.connect((SERVER_HOST, SERVER_PORT))

# Send data to server
message = "Hello, server!"
client_socket.send(message.encode())

# Receive response from server
response = client_socket.recv(1024).decode()
print(f"[*] Server response: {response}")

otp="123456"
p = 149
q = 173

publicu, privateu = generate_key_pair(p, q)
# Receive public key components from server
public_key_message = client_socket.recv(1024).decode()
publics1, publics2 = map(int, public_key_message.split(','))
publics = (publics1, publics2)
print(publicu)
print(publics)

# sending public key to the server
public_key_message = f"{publicu[0]},{publicu[1]}"
client_socket.send(public_key_message.encode())

# encrypting the otp using PUs
Eotp=encrypt(publics,otp)

# sending Encrypted otp to the server
json_data_Eotp = json.dumps(Eotp)
client_socket.send(json_data_Eotp.encode())

# hashing the otp using SHA-256
hashedotp=SHA(otp)
# encrypting the hased otp 
hashedEotp=encrypt(privateu,hashedotp)

# sending the encrypted hashed otp
json_data_hashedEotp = json.dumps(hashedEotp)
client_socket.send(json_data_hashedEotp.encode())

# Close the connection
client_socket.close()