# Library encapsulating cryptography-related functions
# used in this project.
#
# Written by Jackson Murphy. Last updated November 3, 2017

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
# The maximum number of raw bytes allowed in the ssl-record data field,
# before base64 encoding
MAX_DATA_LEN = 16000  # 16 KB
# The size of MAX_DATA_LEN after base64 encoding
MAX_BASE64_DATA_LEN = 21617
# Character length of a message authentication code digest (hexstring)
HMAC_LEN = 64
# Initialization vector 8 bytes long
IV = b"00000000"

# returns a des3 cipher that can be used to encrypt and decrypt messages
def _create_des3_cipher(key, mode, iv):
    cipher = DES3.new(key, mode, iv)
    return cipher

# encrypts a string and returns bytes
def des3_encrypt(key, iv, msg):
    cipher = _create_des3_cipher(key, DES3.MODE_CBC, iv)
    return cipher.encrypt(msg)

# decrypts bytes and returns bytes
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
        print("Hash is invalid!\nExpected:", expected_hash, "\nBut got:", test_hash, "\n")
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

def send_data(data, encryption_key, integrity_key, socket):
    print("Sending file with this many bytes:", len(data), "\n")
    # split the bytes of the file into an array where each el has size MAX_DATA_LEN
    data_arr = bytestr2array(data, MAX_DATA_LEN)
    sequence_num = 0
    msg = b"" # initialize the aggregate message to be sent
    for chunk in data_arr:
        msg += blockify_data(chunk, sequence_num, encryption_key, integrity_key)
        sequence_num += 1
    socket.send(msg)

# returns a SSL-like record block for the data. The difference from a typical
# SSL record is that here the record header only includes data-length
def blockify_data(data, sequence_num, encryption_key, integrity_key):
    data_len = len(base64.encodestring(data))
    data_len_bin = pack("H", data_len) # unsigned 2-byte representation of data_len
    padding_len = DES3_BLOCK_SIZE - ((data_len + HMAC_LEN) % DES3_BLOCK_SIZE)
    padding_len_bin = pack("H", padding_len)
    padding = "0" * padding_len
    record_header = data_len_bin + padding_len_bin
    hmac = get_hmac(sequence_num, record_header, data, integrity_key)
    to_encrypt = base64.encodestring(data).decode() + hmac + padding
    ciphertext = des3_encrypt(encryption_key, IV, to_encrypt)
    block = record_header + ciphertext
    return block

def receive_data(read_decr_key, read_integ_key, socket):
    received_bytes = b"" # initialize
    # get all the records from Bob before processing
    while True:
        received_chunk = socket.recv(4096)
        if len(received_chunk) == 0:
            break
        received_bytes += received_chunk
    print("Alice received data from Bob!\n")
    data = get_data_from_records(received_bytes, read_decr_key, read_integ_key)
    return data


# extracts data from the ssl-like record blocks
def get_data_from_records(received_bytes, read_decr_key, read_integ_key):
    sequence_num = 0 # initialize
    received_bytes_len = len(received_bytes)
    processed_bytes_len = 0
    data = b""
    while processed_bytes_len < received_bytes_len:
        record_header = received_bytes[:4]
        data_len = unpack("H", record_header[:2])[0]
        padding_len = unpack("H", record_header[2:4])[0]
        encrypted_bytes_len = data_len + HMAC_LEN + padding_len
        unencrypted_bytes = des3_decrypt(
            read_decr_key, IV, received_bytes[4:4+encrypted_bytes_len])
        print("Record decrypted")
        record_data = base64.decodestring(unencrypted_bytes[:data_len])
        hmac = unencrypted_bytes[data_len:data_len + HMAC_LEN].decode()
        if hmac_is_invalid(
            hmac, sequence_num, record_header, record_data, read_integ_key):
            print("The hmac was invalid for record number:", sequence_num)
        print("HMAC check passed")
        data += record_data
        print("Finished processing record number:", sequence_num, "\n")
        sequence_num += 1
        if data_len < MAX_BASE64_DATA_LEN: # this was the last record
            break
        # remove the bytes we just looked at
        received_bytes = received_bytes[(len(record_header) + encrypted_bytes_len):]
    return data

# Splits a byte string into an array where each element is el_size long
# (the last element may be shorter)
def bytestr2array(bytestr, el_size):
    bytes_arr = []
    final_arr_len = math.floor(len(bytestr) / el_size) + 1
    print("File was broken up into this many records:", final_arr_len, "\n")
    for i in range(final_arr_len):
        if i == 0:
            bytes_arr.append(bytestr[:el_size])
        elif i == final_arr_len - 1:
            bytes_arr.append(bytestr[el_size * (final_arr_len-1):])
        else:
            bytes_arr.append(bytestr[el_size * i : el_size * (i+1)])
    return bytes_arr

# Returns the SSL hmac as a hex string
def get_hmac(sequence_num, record_header, data, integrity_key):
    m1 = hashlib.sha256()
    m1.update(integrity_key)
    m1.update(str(sequence_num).encode())
    m1.update(record_header)
    m1.update(data)
    inner_hash = m1.digest()
    m2 = hashlib.sha256()
    m2.update(integrity_key)
    m2.update(inner_hash)
    return m2.hexdigest()

# Calculates the hmac of the input parameters (except the first),
# and compares this result with the expected hash (the first parameter)
# Supplied hmac should be in hexstring format
def hmac_is_invalid(hmac, sequence_num, record_header, data, integrity_key):
    calculated_hmac = get_hmac(sequence_num, record_header, data, integrity_key)
    if hmac != calculated_hmac:
        print("Hmac invalid!\n Was expecting:", hmac, "\nBut got:", calculated_hmac, "\n")
        return True
    else:
        return False

# Helper method for Bob.py and Alice.py
def get_app_mode(argv):
    if len(argv) > 1:
        return "corrupted"
    else:
        return "normal"
