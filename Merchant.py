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
        decrAES = decryptor.decrypt(encrAES)
        print("Random Key from Client: ", decrAES)
        AES_key = AES.new(decrAES, AES.MODE_CBC, iv)

        #Decriptam datele cardului
        nameOnCard = AES_key.decrypt(nameOnCardEnc)
        numereCard = AES_key.decrypt(numereCardEnc)
        validThru = AES_key.decrypt(validThruEnc)
        cvv = AES_key.decrypt(cvvEnc)

        print("Nume: ", nameOnCard)
        print("Numar Card:", numereCard)
        print("Data expirare:", validThru)
        print("CVV :", cvvEnc)

        # #Semnatura
        # Sid = b'007'
        # f = open('mykey.pem', 'r')
        # key = RSA.import_key(f.read())
        # h = SHA256.new(Sid)
        # signature = pss.new(key).sign(h)
        # print("Sid: ", Sid)
        # print("Signature:", signature)
        #
        # #Criptam cu AES Sid si SgM(Sid)
        # AES_key.encrypt(Sid)
        # AES_key.encrypt(signature)
        #
        # #Trimitem catre Client Sid si SgM(Sid)
        # c.send(Sid)
        # c.sed(signature)

    finally:
        c.close()
        s.close()


