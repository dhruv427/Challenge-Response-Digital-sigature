import socket
import hashlib
import random
import json

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
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Bind the socket to the address and port
server_socket.bind((SERVER_HOST, SERVER_PORT))
# print("%%%")
# Listen for incoming connections
server_socket.listen(1)
print(f"[*] Listening on {SERVER_HOST}:{SERVER_PORT}")

# Accept incoming connection
client_socket, client_address = server_socket.accept()
print(f"[*] Accepted connection from {client_address[0]}:{client_address[1]}")
print("^^")

# Receive data from client
data = client_socket.recv(1024).decode()
print(f"[*] Received: {data}")

# Send response back to client
response = "Message received!"
client_socket.send(response.encode())

#Close the connection



#running the algo
p = 113
q = 151
publics, privates = generate_key_pair(p, q)

# sending public ket to the user
public_key_message = f"{publics[0]},{publics[1]}"
client_socket.send(public_key_message.encode())

# Receive public key components from client
public_key_message = client_socket.recv(1024).decode()
publicu1, publicu2 = map(int, public_key_message.split(','))
publicu = (publicu1, publicu2)
 
# receive Encrypted otp from the user
json_data_otp = client_socket.recv(1024).decode()
otp = json.loads(json_data_otp)

# Receive encrypted hased otp from the iser
json_data_hashedotp = client_socket.recv(1024).decode()
hashedotp = json.loads(json_data_hashedotp)

# decrypting encrypted otp
Dotp=decrypt(privates,otp)
Dhasedotp=decrypt(publicu,hashedotp)
 

hashedDotp=SHA(Dotp)

if(hashedDotp==Dhasedotp):
    print("Verified")
else:
    print("Not verified")

 

client_socket.close()
server_socket.close()