from OpenSSL import crypto
from Crypto.PublicKey import RSA

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

# convert to bits
msg = crypto.dump_certificate(crypto.FILETYPE_PEM, cert)

# convert back, verify certificate and get public key
certificate = crypto.load_certificate(crypto.FILETYPE_PEM, msg)
pubkey_bob = certificate.get_pubkey()
sender = certificate.get_subject().commonName
print("The sender was:", sender)

# Encoded a nonce with bob's public key
nonce = "abcd"

public_key_file = open("pub_key_bob.pem", "wb+")
public_key_file.write(crypto.dump_publickey(crypto.FILETYPE_PEM, pubkey_bob))
public_key_file.close()
public_key_string = open(public_key_file, "r").read()
pubkey = RSA.importKey(public_key_string)
pubkey.encrypt(nonce)
print("finished!")
