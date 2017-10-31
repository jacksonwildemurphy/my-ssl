# Written by Jackson Murphy. Last updated October 31, 2017.

import Crypto_lib as crypto

# Returns the names of the algorithms Alice wants to use to communicate,
# and also returns Alice's certificate
# the message has the format <encryption algorithm>;<integ. algorithm>;<certificate>
def _parse_first_msg(msg):
    # find the locations of the 2 delimiters to properly parse message
    delimiter = b";"
    delimiter_1_index, delimiter_2_index = -1, -1
    for i in range(len(msg)):
        if msg[i] == delimiter:
            if delimiter_1_index == -1:
                delimiter_1_index = i
            else:
                delimiter_2_index = i
                break
    encryption_alg = msg[:delimiter_1_index].decode()
    integrity_protection_alg = msg[delimiter_1_index+1:delimiter_2_index].decode()
    certificate = msg[delimiter_2_index+1:]
    print("Got these algorithms:", encryption_alg, "and", integrity_protection_alg)
    return [encryption_alg, integrity_protection_alg, certificate]


def _send_cert_and_encrypted_nonce(certificate, bobs_encrypted_nonce, socket):
    msg = certificate + bobs_encrypted_nonce
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
    bobs_encrypted_nonce = crypto.encrypt_with_publickey(bobs_nonce, alices_publickey)
    first_msg_to_alice = _send_cert_and_encrypted_nonce(bobs_certificate, bobs_encrypted_nonce, connection_socket)

    # Receive Alice's nonce encrypted with Bob's public key
    second_msg_from_alice = connection_socket.recv(1024)
    alices_encrypted_nonce = second_msg_from_alice
    bobs_privatekey = crypto.get_privatekey(key_pair)
    alices_nonce = crypto.decrypt_with_privatekey(alices_encrypted_nonce, bobs_privatekey)

    # Get a master secret from the  two nonces
    master_secret = crypto.get_master_secret(bobs_nonce, alices_nonce)

    # Compute a keyed hash of the master secret, previous handshake messages, and "SERVER"
    messages = [first_msg_from_alice, first_msg_to_alice, second_msg_from_alice]
    keyed_hash = crypto.hash_handshake(master_secret, messages, "SERVER")
    connection_socket.send(keyed_hash.encode())

    # Receive Alice's hash of the handshake and verify it
    alices_hash = connection_socket.recv(1024).decode()
    if crypto.hash_is_invalid(alices_hash, master_secret, messages, "CLIENT"):
        print("Received a bad hash from Alice!")







    pass
