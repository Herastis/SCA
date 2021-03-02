import time
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Cipher import AES
from Crypto.Signature import pss
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from threading import Thread
from Crypto import Random
import socket
from _thread import *

#c = client
host = 'localhost'
port = 9009
iv = b'12345678abcdefgh'

# Cheia AES pentru M si PG
key_mpg = get_random_bytes(16)
AES_MPG = AES.new(key_mpg, AES.MODE_EAX)

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
        # cheia publica a clientului
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
        Pas3 = c.recv(5120)
        print("Pas3 :", Pas3)
        publicKey_PG = c.recv(1024)
        pas3 = Pas3.split(b' # ')
        pm = pas3[0]
        po = pas3[1]
        print("po criptat", po)
        keyaes = AES.new(decrAES, AES.MODE_EAX, AES_key.nonce)
        po_decr = keyaes.decrypt(po)
        print('Po decrypt ', po_decr)
        po_list = po.split(b' # ')
        pubKC = keyaes.decrypt(public_keyEnc)

        #Semnam sid, pubKC si amount cu cheia privata a lui M
        sigM = po_list[0] + pubKC + bytes(public_key[1])
        f = open('mykey.pem', 'r')
        key = RSA.import_key(f.read())
        h = SHA256.new(sigM)
        signature = pss.new(key).sign(h)
        print("Signature:", signature, end='\n\n')
        sigM_enc = AES_MPG.encrypt(sigM)

        #Criptez cheia AES dntre M si PG cu cheia pubilca a lui PG
        f = open('RSA_PrivKPG.pem', 'r')
        keyPG = RSA.import_key(f.read())
        encryptor = PKCS1_OAEP.new(keyPG)
        Aes_mg_enc = encryptor.encrypt(key_mpg)
        thread.start_new_thread()
        c.send(pm)
        time.sleep(0.2)
        c.send(sigM_enc)
        time.sleep(0.2)
        c.send(Aes_mg_enc)

    finally:
        c.close()
        s.close()


