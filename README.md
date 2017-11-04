# My SSL
## A commandline demo showing Alice and Bob securely communicating with an SSL-like protocol
Alice is a client and Bob is a server. They mutually authenticate each other with self-signed certificates and generate four unidirectional keys for encryption and message integrity. Then Bob sends Alice a large file using a record format very similar to that used by SSLv3

## How to Run

First start Bob:    `$ python Bob.py`

Then start Alice:   `$ python Alice.py`
  

Note: requires python 3.6
