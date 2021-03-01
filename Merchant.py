import time
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
    RSA_keys = RSA.generate(1024)
    private_key = RSA_keys.exportKey()
    f = open('mykey.pem', 'wb')
    f.write(RSA_keys.export_key('PEM'))
    f.close()


    print("Private key: ",private_key)
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(('127.0.0.1', port))
    s.listen(1)
    c, addr = s.accept()
    try:
        #Trimitem cheia public catre client
        c.send(RSA_keys.publickey().exportKey(format='PEM', passphrase=None, pkcs=1))

        #Primim mesajul criptat (cheia AES criptata)
        encrAES = c.recv(1024)

        #Primim datele cardului
        nameOnCardEnc = c.recv(1024)
        numereCardEnc = c.recv(1024)
        validThruEnc = c.recv(1024)
        cvvEnc = c.recv(1024)

        #Obtinem decr cu care decriptam datele cardului criptate cu AES
        decryptor = PKCS1_OAEP.new(RSA_keys)
        decrAES = decryptor.decrypt(encrAES) #sir random caracter din client
        print("Random Key from Client: ", decrAES, end='\n\n')
        AES_key = AES.new(decrAES, AES.MODE_EAX, iv)


        #Decriptam datele cardului
        nameOnCard = AES_key.decrypt(nameOnCardEnc)
        numereCard = AES_key.decrypt(numereCardEnc)
        validThru = AES_key.decrypt(validThruEnc)
        cvv = AES_key.decrypt(cvvEnc)

        print("Nume: ", nameOnCard)
        print("Numar Card:", numereCard)
        print("Data expirare:", validThru)
        print("CVV :", cvvEnc, end='\n\n')

        #Semnatura
        Sid = b'007             '
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

    finally:
        c.close()
        s.close()


