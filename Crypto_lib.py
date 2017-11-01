# Library encapsulating cryptography-related functions
# used in this project.
#
# Written by Jackson Murphy. Last updated October 31, 2017

import base64
from Crypto.Cipher import DES3
from Crypto.PublicKey import RSA
import hashlib
import math
from OpenSSL import crypto
import secrets
from struct import *

# Encryption block size for 3DES
DES3_BLOCK_SIZE = 64
# Initialization vector 8 bytes long
IV = b"00000000"

# returns a des3 cipher that can be used to encrypt and decrypt messages
def _create_des3_cipher(key, mode, iv):
    cipher = DES3.new(key, mode, iv)
    return cipher


def des3_encrypt(key, iv, msg):
    cipher = _create_des3_cipher(key, DES3.MODE_CBC, iv)
    return cipher.encrypt(msg)


def des3_decrypt(key, iv, msg):
    cipher = _create_des3_cipher(key, DES3.MODE_CBC, iv)
    result = cipher.decrypt(msg)
    return result

# Returns an X509 certificate and an RSA key pair
def create_certificate(name):
    key_pair = crypto.PKey()
    key_pair.generate_key(crypto.TYPE_RSA, 2048)
    # create a self-signed certificate
    cert = crypto.X509()
    cert.set_serial_number(1)
    cert.get_issuer().commonName = name
    cert.get_subject().commonName = name
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(200) # certificate is valid for 200 seconds
    cert.set_pubkey(key_pair)
    cert.sign(key_pair, "sha256")
    return [key_pair, cert]

def certificate2bytes(certificate):
    return crypto.dump_certificate(crypto.FILETYPE_PEM, certificate)

def bytes2certificate(bits):
    return crypto.load_certificate(crypto.FILETYPE_PEM, bits)
# Returns True if the certificate is expired or the subject's common name
# doesn't match what is expected
def is_invalid_certificate(certificate, expected_name):
    if certificate.get_subject().commonName != expected_name:
        return True
    else:
        return False

# Returns an RSA  public key from a certificate
def get_publickey(certificate):
    public_key_file = open("public_key.pem", "wb+")
    cert_publickey = certificate.get_pubkey()
    public_key_file.write(crypto.dump_publickey(crypto.FILETYPE_PEM, cert_publickey))
    public_key_file.close()
    public_key = RSA.importKey(open("public_key.pem").read())
    # TODO delete file
    return public_key

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
        return publickey.encrypt(data, b"ignored")[0] # nonce is 1st el of tuple
    elif type(data) is str:
        return publickey.encrypt(data.encode(), b"ignored")[0]
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
    m = hashlib.sha256()
    m.update(str(master_secret).encode())
    for msg in messages:
        m.update(msg)
    m.update(role.encode())
    return m.hexdigest()

# Compares test_hash with a newly generated hash from the master secret,
# messages, and the role
def hash_is_invalid(test_hash, master_secret, messages, role):
    expected_hash = hash_handshake(master_secret, messages, role)
    if test_hash != expected_hash:
        print("Hash is invalid! Expected:", expected_hash, "But got:", test_hash )
        return True
    else:
        return False

# Returns four 128-bit byte strings that can be used as 128-bit keys
def generate_keys_from_handshake(master_secret, nonce1, nonce2):
    m = hashlib.sha3_512()
    m.update(str(master_secret).encode())
    m.update(str(nonce1).encode())
    m.update(str(nonce2).encode())
    digest = m.digest()
    key1 = digest[:16]
    key2 = digest[16:32]
    key3 = digest[32:48]
    key4 = digest[48:]
    return [key1, key2, key3, key4]

def my_ssl_send_file(file, encryption_key, integrity_key, socket):
    file_bytes = file.read()
    print("File is this many bytes:", len(file_bytes))
    MAX_DATA_LEN = 16000  # 16 KB
    # split the bytes of the file into an array where each el has size MAX_DATA_LEN
    file_bytes_arr = bytestr2array(file_bytes, MAX_DATA_LEN)
    sequence_num = 0
    msg = b"" # initialize the aggregate message to be sent
    for chunk in file_bytes_arr:
        msg += blockify_data(chunk, sequence_num, encryption_key, integrity_key)
        sequence_num += 1
    print("Message to send to alice is this long:", len(msg))
    socket.send(msg)

# returns a SSL-like record block for the data. The difference from a typical
# SSL record is that here the record header only includes data-length
def blockify_data(data, sequence_num, encryption_key, integrity_key):
    data_len = len(base64.encodestring(data))
    print("Data length before encoding was:", len(data))
    print("Data length after encoding is:", data_len)
    #print("Data length after decoding is:", len(base64.encodestring(data).decode()))
    data_len_bin = pack("H", data_len) # unsigned 2-byte representation of data_len
    hmac = get_hmac(sequence_num, data_len_bin, data, integrity_key)
    padding_len = DES3_BLOCK_SIZE - ((data_len + len(hmac)) % DES3_BLOCK_SIZE)
    padding = "0" * padding_len
    to_encrypt = base64.encodestring(data).decode() + hmac + padding
    ciphertext = des3_encrypt(encryption_key, IV, to_encrypt)
    block = data_len_bin + ciphertext
    print("block has size:", len(block))
    print("Test!")
    print("Encoded bytes:", base64.encodestring(b"hello"))
    print("Decoded encoded bites:", base64.encodestring(b"hello").decode())
    print("Should be original:", base64.decodestring(base64.encodestring(b"hello").decode()))
    return block


def bytestr2array(bytestr, el_size):
    bytes_arr = []
    final_arr_len = math.floor(len(bytestr) / el_size) + 1
    print("File is broken up into this many pieces:", final_arr_len)
    for i in range(final_arr_len):
        if i == 0:
            bytes_arr.append(bytestr[:el_size])
        elif i == final_arr_len - 1:
            bytes_arr.append(bytestr[el_size * (final_arr_len-1):])
        else:
            bytes_arr.append(bytestr[el_size * i : el_size * (i+1)])
    return bytes_arr

# Returns the SSL hmac as a hex string
def get_hmac(sequence_num, data_len_bin, data, integrity_key):
    m1 = hashlib.sha256()
    m1.update(integrity_key)
    m1.update(str(sequence_num).encode())
    m1.update(data_len_bin)
    m1.update(data)
    inner_hash = m1.digest()
    m2 = hashlib.sha256()
    m2.update(integrity_key)
    m2.update(inner_hash)
    return m2.hexdigest()



# convert to bits
# msg = crypto.dump_certificate(crypto.FILETYPE_PEM, cert)

# convert back, verify certificate and get public key
