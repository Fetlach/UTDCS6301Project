# Server program to execute encryption/decryption 
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
from secretshare import Secret, SecretShare, Share
import json
import socket
import KeyFragmenter

s = socket.socket()
num_procs = 2

port = 41398
print("Socket created")
s.bind(('', port))
print("socket binded to %s" %port)

print("socket is listening")

encrypt_sockets = []

decrypt_sockets = []

ports = 41399

# Function that uses the current encrypt_sockets to create a shared key and encrypt.
def encrypt_msg(message, encrypt_sockets):
    print("Encrypting!")
    private_keys = []
    public_keys = []
    secret = message.encode('utf-8')
    my_secret = Secret(KeyFragmenter.encode_secret_from_bytes(secret))

    for i in range(num_procs):
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )

        public_key = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        public_keys.append(public_key)
        private_keys.append(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption())
        )

    # Create json container
    shares_json = {
        "public_keys": public_keys,
        "private_keys": private_keys,
        "shares": [],
        "share_positions": [],
        "numShares": []
    }

    shares = KeyFragmenter.fragmentKeyAndEncrypt(my_secret, shares_json, num_procs)
    
    # Distribute shares amongst the processes
    index = 0
    for item in shares["shares"]:
        encrypt_sockets[index].send(str(public_keys[index]).encode())
        encrypt_sockets[index].send((str(index)).encode())
        encrypt_sockets[index].send(str(item).encode())
        print(item)
        encrypt_sockets[index].close()
        index += 1
    print("Encryption complete!")
# end encrypt()



s.listen(5)
while True:
    c, addr = s.accept()
    print("Connection received")
    print(addr)
    code = c.recv(2048).decode()
    print(code)

    if code == "Encrypt":
        # This is the first encrypt - get the message from them.
        if len(encrypt_sockets) == 0:
            print("Host found! Obtaining message")
            c.send("host".encode())
            enc_msg = c.recv(2048).decode()
            print(enc_msg)
        else :
            c.send("notHost".encode())
        
        # Assign socket to the new process.
        sock_next = socket.socket()
        sock_next.bind(('', ports))
        sock_next.listen()
        print("Waiting for client to connect!")
        c.send(str(ports).encode())
        conn_next, addr_next = sock_next.accept()
        encrypt_sockets.append(conn_next)
        c.close()
        ports += 1
        # Begin encryption process if correct number of processes have been made
        if len(encrypt_sockets) == num_procs:
            encrypt_msg(str(enc_msg), encrypt_sockets)
            # Clear encryption sockets
            encrypt_sockets = []
# end while

            



            