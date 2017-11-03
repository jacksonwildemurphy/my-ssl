# Written by Jackson Murphy. Last updated October 31, 2017.

import Crypto_lib as crypto
from socket import *

# Returns the names of the algorithms Alice wants to use to communicate,
# and also returns Alice's certificate
# the message has the format <encryption algorithm>;<integ. algorithm>;<certificate>
def _parse_first_msg(msg):
    # find the locations of the 2 delimiters to properly parse message
    delimiter = ";"
    delimiter_1_index, delimiter_2_index = -1, -1
    for i in range(len(msg)):
        if chr(msg[i]) == delimiter:
            if delimiter_1_index == -1:
                delimiter_1_index = i
            else:
                delimiter_2_index = i
                break
    encryption_alg = msg[:delimiter_1_index].decode()
    integrity_protection_alg = msg[delimiter_1_index+1:delimiter_2_index].decode()
    certificate = crypto.bytes2certificate(msg[delimiter_2_index+1:])
    return [encryption_alg, integrity_protection_alg, certificate]


def _send_cert_and_encrypted_nonce(certificate, bobs_encrypted_nonce, socket):
    certificate_bytes = crypto.certificate2bytes(certificate)
    msg = certificate_bytes + bobs_encrypted_nonce
    socket.send(msg)
    return msg




##### START OF PROGRAM #####

# Set up server
server_port = 12000
server_socket = socket(AF_INET, SOCK_STREAM)
server_socket.bind(("", server_port))
server_socket.listen(1)

while 1:
    connection_socket, addr = server_socket.accept()
    first_msg_from_alice = connection_socket.recv(1024)
    [encryption_alg, integrity_protection_alg, alices_cert] = _parse_first_msg(first_msg_from_alice)
    if crypto.is_invalid_certificate(alices_cert, "Alice"):
        print("Alice's certificate is invalid!")

    # Create a certificate and nonce. Send these to Alice
    [key_pair, bobs_certificate] = crypto.create_certificate("Bob")
    alices_publickey = crypto.get_publickey(alices_cert)
    bobs_nonce = crypto.create_nonce()
    print("Created nonce:", bobs_nonce, "\n")
    bobs_encrypted_nonce = crypto.encrypt_with_publickey(str(bobs_nonce), alices_publickey)
    first_msg_to_alice = _send_cert_and_encrypted_nonce(bobs_certificate, bobs_encrypted_nonce, connection_socket)

    # Receive Alice's nonce encrypted with Bob's public key
    second_msg_from_alice = connection_socket.recv(1024)
    alices_encrypted_nonce = second_msg_from_alice
    bobs_privatekey = crypto.get_privatekey(key_pair)
    alices_nonce = (crypto.decrypt_with_privatekey(alices_encrypted_nonce, bobs_privatekey))
    alices_nonce = int(alices_nonce.decode())
    print("Alice's nonce is:", alices_nonce, "\n")

    # Get a master secret from the  two nonces
    master_secret = crypto.get_master_secret(bobs_nonce, alices_nonce)
    print("Got master secret:", master_secret, "\n")

    # Compute a keyed hash of the master secret, previous handshake messages, and "SERVER"
    messages = [first_msg_from_alice, first_msg_to_alice, second_msg_from_alice]
    keyed_hash = crypto.hash_handshake(master_secret, messages, "SERVER")
    connection_socket.send(keyed_hash.encode())

    # Receive Alice's hash of the handshake and verify it
    alices_hash = connection_socket.recv(1024).decode()
    if crypto.hash_is_invalid(alices_hash, master_secret, messages, "CLIENT"):
        print("Received a bad hash from Alice!\n")
    else:
        print("Alice's keyed hash passes verification!\n")

    # Derive encryption and integrity protection keys from the handshake
    [read_decr_key, write_encr_key, read_integ_key, write_integ_key] = \
        crypto.generate_keys_from_handshake(master_secret, alices_nonce, bobs_nonce)
    print("Generated the 4 keys\n\nHandshake complete!\n")

    # Securely send a file to Alice
    f = open("2017PA4.pdf", "rb")
    file_bytes = f.read()
    crypto.send_data(file_bytes, write_encr_key, write_integ_key, connection_socket)

    # all done
    connection_socket.close()
