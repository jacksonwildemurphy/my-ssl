# Written by Jackson Murphy. Last updated October 31, 2017

import Crypto_lib as crypto

def _send_algs_and_cert(encryption_alg, integrity_protection_alg, certificate, socket):
    # delimit algorithms with a semicolon
    delimiter = ";".encode()
    msg = encryption_alg + delimiter + integrity_protection_alg + delimiter + certificate
    socket.send(msg)
    return msg

# Returns Bob's certificate and his decrypted nonce
def _parse_first_msg(msg, key_pair):
    certificate_len = x
    certificate_bytes = msg[:certificate_len]
    certificate = crypto.load_certificate(crypto.FILETYPE_PEM, certificate_bytes)
    encrypted_nonce = msg[certificate_len:]
    alices_privatekey = crypto.get_privatekey(key_pair)
    nonce = crypto.decrypt_with_privatekey(encrypted_nonce)
    return [certificate, nonce]


def _send_encrypted_nonce(alices_encrypted_nonce, socket):
    socket.send(alices_encrypted_nonce)
    return alices_encrypted_nonce


##### START OF PROGRAM ####

# Alice dictates which algorithms to use in communicating with Bob
encryption_alg = b"3DES"
integrity_protection_alg = b"SHA-256"
[key_pair, certificate] = crypto.create_certificate("Alice")

# Open a TCP connection with Bob
server_name = "localhost"
server_port = 12000 # the port Bob is listening on
client_socket = socket(AF_INET, SOCK_STREAM)
client_socket.connect((server_name, server_port))

# Send a message to Bob specifying the algorithms to use for communicating and
# Alice's certificate so Bob can authenticate her
first_msg_to_bob = _send_algs_and_cert(encryption_alg, integrity_protection_alg, certificate, client_socket)

# Receive Bob's response, verify his certificate, and get his public key
first_msg_from_bob = client_socket.recv(1024)
[bobs_cert, bobs_nonce] = _parse_first_msg(first_msg_from_bob, key_pair)
if crypto.is_invalid_certificate(bobs_cert, "Bob"):
    print("Bob's certificate is invalid!")
bobs_publickey = crypto.get_publickey(bobs_cert)

# Create a nonce, encrypt it, and send it to Bob
alices_nonce = crypto.create_nonce()
alices_encrypted_nonce = crypto.encrypt_with_publickey(alices_nonce, bobs_publickey)
second_msg_to_bob = _send_encrypted_nonce(alices_encrypted_nonce, client_socket)

# Get a master secret from the  two nonces
master_secret = crypto.get_master_secret(bobs_nonce, alices_nonce)

# Compute a keyed hash of the master secret, previous handshake messages, and "CLIENT"
messages = [first_msg_to_bob, first_msg_from_bob, second_msg_to_bob]
keyed_hash = crypto.hash_handshake(master_secret, messages, "CLIENT")

# Receive Bob's hash of the handshake and verify it
bobs_hash = client_socket.recv(1024).decode()
if crypto.hash_is_invalid(bobs_hash, master_secret, messages, "SERVER"):
    print("Received a bad hash from Alice!")

# Send Bob our hash of the handshake
connection_socket.send(keyed_hash.encode())



















    pass