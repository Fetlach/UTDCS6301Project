# Program to run client-side that will interact with the AWS server instance and transfer encrypted files.

# Each 
import socket

sock = socket.socket()
port = 41398
server_ip = "localhost"

while True:
    print("Are you encrypting or decrypting a message? (Input e for encryption, d for decryption)")
    mode = input()
    if mode == "e":
        break
    
    if mode == "d":
        break

match mode:
    case "d":
        print("Decryption selected.") 
    case "e":
        # Get the message needed to encrypt.
        print("Encryption selected.")
        print("What is the message you are attempting to send?")
        message = input()
        print("Chosen string: " + message)

        # Connect to server and send intended message.
        print("Connecting to server at " + server_ip)
        sock = socket.socket()
        sock.connect((server_ip, port))
        print("Connected!")
        sock.send("Encrypt".encode())
        response = sock.recv(2048).decode()

        # If this is the first client to request an encrypt,
        # send the message to be encrypted.
        if response == "host":
            print("Host! Sending item to be encrypted...")
            sock.send(message.encode())

        else:
            print("Not the host!")

        # Get personal client port to connect
        print()
        print("Waiting for new socket...")
        newPort = int(sock.recv(2048).decode())
        sock.close()

        # Connect to personal port
        print()
        print("Connecting to secondary socket at %i" %newPort)
        sock_personal = socket.socket()
        sock_personal.connect((server_ip, newPort))


        # Wait for server
        print()
        print("Waiting for other members to join...")

        # Receive personal key
        print()
        print("Receiving personal key...")
        personalKey = sock_personal.recv(2048).decode()
        print(personalKey)


        # Receive position
        print()
        print("Receiving personal position...")
        position = sock_personal.recv(1).decode()
        print(position)

        # Receive encrypted message
        print()
        print("Receiving personal share...")
        encryptedMessage = sock_personal.recv(4096).decode()
        print("Message received!")
        print(encryptedMessage)

        # Close socket and exit
        sock_personal.close()
        exit()


