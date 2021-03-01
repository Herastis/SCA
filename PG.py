import socket
import time
from Cryptodome.PublicKey import RSA
from Cryptodome.Cipher import PKCS1_OAEP
from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes
from Cryptodome.Hash import SHA256
from Cryptodome.Signature import pss

host = "localhost"
port = 9009

#----Optrional
#Customer
if __name__ == '__main__':
    #1.a) Generam cheile RSA ale clientului
    RSA_Ckey = RSA.generate(1024)
    f = open('RSA_PubKPG.pem', 'wb')
    f.write(RSA_Ckey.publickey().exportKey('PEM'))
    f.close()
    f = open('RSA_PrivKPG.pem', 'wb')
    f.write(RSA_Ckey.exportKey('PEM'))
    f.close()
    print("Da")