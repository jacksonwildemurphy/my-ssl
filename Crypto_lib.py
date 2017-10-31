# Library encapsulating cryptography-related functions
# used in this project.
#
# Written by Jackson Murphy. Last updated October 31, 2017

import base64
from Crypto.Hash import SHA
from Crypto.PublicKey import RSA
from OpenSSL import crypto
import secrets

# Returns an X509 certificate and an RSA key pair
def create_certificate(name):
    key_pair = crypto.PKey()
    key_pair.generate_key(crypto.TYPE_RSA, 2048)
    # create a self-signed certificate
    cert = crypto.X509()
    cert.set_serial_number(1)
    cert.get_issuer().commonName = "Bob"
    cert.get_subject().commonName = "Bob"
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(200) # certificate is valid for 200 seconds
    cert.set_pubkey(key_pair)
    cert.sign(key_pair, "sha256")
    return [key_pair, cert]

# Returns True if the certificate is expired or the subject's common name
# doesn't match what is expected
def is_invalid_certificate(certificate, expected_name):
    if certificate.get_subject().commonName != expected_name:
        return True
    else:
        return False

# Extracts the public key from a certificate and returns it
def get_publickey(certificate):
    return certificate.get_pubkey()

# Returns an RSA private key object from a PKey key pair
def get_privatekey(key_pair):
    private_key_file = open("private_key.pem", "wb+")
    private_key_file.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, key_pair))
    private_key_file.close()
    private_key = RSA.importKey(open("private_key.pem").read())
    # TODO delete file
    return private_key

# Returns encrypted data with the public key
def encrypt_with_publickey(data, publickey):
    if type(data) is bytes:
        return publickey.encrypt(data, b"ignored")
    elif type(data) is str:
        return publickey.encrypt(data.encode(), b"ignored")
    else:
        raise Exception("Expected data type of bytes or str but got:", type(data))

# Returns decrypted data
def decrypt_with_privatekey(data, privatekey):
    return privatekey.decrypt(data)

# Returns a 64-bit random integer
def create_nonce():
    return secrets.randbits(64)

# Xor's two numbers and returns the result
def get_master_secret(n1, n2):
    return n1 ^ n2

# Returns the hash of the input parameters concatenated together
# messages is an array of bytes objects, role will be "SERVER" or "CLIENT"
def hash_handshake(master_secret, messages, role):
    contents = ""
    contents += str(master_secret)
    # convert messages to strings
    for msg in messages:
        msg_64 = base64.encode(msg)
        contents += base64.decode(msg_64)
    contents += role
    h = SHA.new(contents)
    print("Hashed handshake was:", h)
    return h

# Compares test_hash with a newly generated hash from the master secret,
# messages, and the role
def hash_is_invalid(test_hash, master_secret, messages, role):
    expected_hash = hash_handshake(master_secret, messages, role)
    if test_hash != expected_hash:
        print("Hash is invalid! Expected:", expected_hash, "But got:", test_hash )
        return True
    else:
        return False


# convert to bits
# msg = crypto.dump_certificate(crypto.FILETYPE_PEM, cert)
#
# # convert back, verify certificate and get public key
# certificate = crypto.load_certificate(crypto.FILETYPE_PEM, msg)
# pubkey_bob = certificate.get_pubkey()
# sender = certificate.get_subject().commonName
# print("The sender was:", sender)
#
# # Encoded a nonce with bob's public key
# nonce = b"abcd"
#
# public_key_file = open("pub_key_bob.pem", "wb+")
# public_key_file.write(crypto.dump_publickey(crypto.FILETYPE_PEM, pubkey_bob))
# public_key_file.close()
#
# pubkey = RSA.importKey(open("pub_key_bob.pem").read())
# ciphertext = pubkey.encrypt(nonce, b"ignored")
#
# private_key_file = open("private_key.pem", "wb+")
# private_key_file.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, key_pair))
# private_key_file.close()
# private_key = RSA.importKey(open("private_key_bob.pem").read())
#
# original_nonce = private_key.decrypt(ciphertext)

# print("finished!")
# print("nonce was:", original_nonce)