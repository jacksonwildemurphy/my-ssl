README for PA4, Network Security cs5490 University Of Utah
Written by Jackson Murphy. Last updated November 3, 2017

Note: requires python 3.6

How to run:

  1) Successful authentication and file transfer

  First start up Bob (the server):
  $ python Bob.py

  Then start up Alice (the client):
  $ python Alice.py

  2) Corrupted keyed hash during handshake

  $ python Bob.py -v corrupted
  $ python Alice.py
