import time
import random
from Cryptodome.Cipher import AES, PKCS1_OAEP
from Cryptodome.Cipher import AES
from Cryptodome.Signature import pss
from Cryptodome.Hash import SHA256
from Cryptodome.PublicKey import RSA
from Cryptodome.Random import get_random_bytes
from Cryptodome import Random
import socket

#c = client
host = 'localhost'
port = 9009
iv = b'12345678abcdefgh'
if __name__ == '__main__':
    #1.b) Generam cheile RSA ale merchantului
    RSA_Mkeys = RSA.generate(1024)
    public_key = RSA_Mkeys.publickey().exportKey()
    private_key = RSA_Mkeys.exportKey()

    # f = open('mykey.pem', 'wb')
    # f.write(RSA_Mkeys.export_key('PEM'))
    # f.close()

    print("Private key: ",private_key)
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(('127.0.0.1', port))
    s.listen(1)
    c, addr = s.accept()
    try:
        #1)Trimitem cheia publica RSA catre client si primim cheia publica a clientului:
        c.send(RSA_Mkeys.publickey().exportKey(format='PEM', passphrase=None, pkcs=1)) # M -> C
        public_keyEnc = c.recv(1024) # C -> M

        #Primim cheia AES criptata
        encrAES = c.recv(1024)

        # #Primim datele cardului
        # nameOnCardEnc = c.recv(1024)
        # numereCardEnc = c.recv(1024)
        # validThruEnc = c.recv(1024)
        # cvvEnc = c.recv(1024)

        #Obtinem decr cu care decriptam datele cardului criptate cu AES
        decryptor = PKCS1_OAEP.new(RSA_Mkeys)
        decrAES = decryptor.decrypt(encrAES) #sir random caracter din client
        print("Random Key from Client: ", decrAES, end='\n\n')
        AES_key = AES.new(decrAES, AES.MODE_EAX, iv)


        #Semnatura
        #PASUL 2

        Sid = b'1000'
        #Semnatura pe SID
        f = open('mykey.pem', 'r')
        key = RSA.import_key(f.read())
        h = SHA256.new(Sid)
        signature = pss.new(key).sign(h)
        print("Sid:", Sid)
        print("Signature:", signature, end='\n\n')

        #Recream aceeasi cheie AES pentru criptare
        aes_key = AES.new(decrAES, AES.MODE_EAX, AES_key.nonce)

        #Criptam cu AES Sid si SgM(Sid)
        SidEnc = aes_key.encrypt(Sid)
        signatureEnc = aes_key.encrypt(signature)
        print("Sid encrypted: ", SidEnc)
        print("Signature encrypted: ", signatureEnc)

        #Trimitem catre Client Sid si SgM(Sid) criptate
        c.send(SidEnc)
        time.sleep(0.2)
        c.send(signatureEnc)
        time.sleep(0.2)

        #Primim datele criptate de la pasul 3
        Pas3 = c.recv(1024)
        print("Pas3 :", Pas3)
        publicKey_PG = c.recv(1024)


    finally:
        c.close()
        s.close()


