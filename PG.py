import socket
import time
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA256

RSA_Ckey = RSA.generate(1024)
f = open('RSA_PubKPG.pem', 'wb')
f.write(RSA_Ckey.publickey().exportKey('PEM'))
f.close()
f = open('RSA_PrivKPG.pem', 'wb')
f.write(RSA_Ckey.exportKey('PEM'))
f.close()

host = "localhost"
port = 9010
c = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
c.connect((host, port))

pm = c.recv(1024)
sigM = c.recv(1024)
AES_mpg = c.recv(1024)

