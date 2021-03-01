import socket
import time
from Cryptodome.PublicKey import RSA
from Cryptodome.Cipher import PKCS1_OAEP
from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes
from Cryptodome.Signature import pss
from Cryptodome.Hash import SHA256

host = "localhost"
port = 9009

#----Optrional
#Customer
def key_generator():
    # return Random.get_random_bytes(16)
    new_key = RSA.generate(1024)
    public_key = new_key.publickey().exportKey()
    private_key = new_key.exportKey()
    return public_key, private_key
print(key_generator())
#---------------------------------------------------

#Card and payment details-------
nameOnCard = b'Culai Vasile-Ion'
nrCard = b'4367110087623798'
validThru = b'09/23' #strftime maybe
cvv = b'100'
amount = b'100$'
nc = b'03916'
m = b'MULQ3'
OrderDesc = "Cartofi moi si buni la 100$ jumatatea de kilogram"
#-------------------------------
iv = b'12345678abcdefgh'

if __name__ == '__main__':
    #public, private = key_generator()
    sb = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sb.connect((host, port))

    try:
        #Public key primit de la Merchant
        pub_key = RSA.importKey(sb.recv(1024), passphrase=None)
        print("Public key:", pub_key)

        #Criptam prin AES datele cardului
        key = get_random_bytes(16)
        AES_key = AES.new(key, AES.MODE_EAX, iv)

        print("Random Key: ", key, end='\n\n')
        #Criptam numerele cardului, data de expirare, cvv
        nameOnCardEnc = AES_key.encrypt(nameOnCard)
        numereCardEnc = AES_key.encrypt(nrCard)
        validThruEnc = AES_key.encrypt(validThru)
        cvvEnc = AES_key.encrypt(cvv)
        amountEnc = AES_key.encrypt(amount)

        # Cheia AES criptata cu cea publica
        encryptor = PKCS1_OAEP.new(pub_key)
        encrAES = encryptor.encrypt(key)

        #Trimitem mesajul criptat la Merchant
        sb.sendall(encrAES)

        #Trimitem datele cardului criptate
        sb.send(nameOnCardEnc)
        time.sleep(0.2)
        sb.send(numereCardEnc)
        time.sleep(0.2)
        sb.send(validThruEnc)
        time.sleep(0.2)
        sb.send(cvv)

        # Recream aceeasi cheie AES pentru criptare
        aes_key = AES.new(key, AES.MODE_EAX, AES_key.nonce)

        #Primim de la Merchant Sid si SgM(Sid) criptate
        SidEnc = sb.recv(1024)
        print("Sid encrypted: ", SidEnc)

        signatureEnc = sb.recv(1024)
        print("Signature encrypted:", signatureEnc, end='\n\n')

        Sid = aes_key.decrypt(SidEnc)
        print("Sid: ", Sid)

        signature = aes_key.decrypt(signatureEnc)
        print("Signature: ", signature, end='\n\n')

        #PI----------------------------------------------------------->
        #PI(concatenarea)
        pi = nameOnCard + validThru + nrCard + Sid + amount + nc + m #+ pb_key
        print("Date concatenate: ", pi)

        #Aplicam semnatura pe PI
        f = open('mykey.pem', 'r')
        key = RSA.import_key(f.read())
        h = SHA256.new(pi)
        signaturePI = pss.new(key).sign(h)
        print("Semnatura datelor concatenate: ", signaturePI, end='\n\n')

        #Criptez pi si signaturePI cu AES
        piEnc = AES_key.encrypt(pi)
        signaturePIEnc = AES_key.encrypt(signaturePI)
        print("PI criptat: ", piEnc)
        print("Semnatura PI criptat: ", signaturePIEnc)
        # PI<-----------------------------------------------------------

        #PO----------------------------------------------------------->
        # #SigC(concatenarea)
        # sigC =  Sid + amount + nc # + OrderDesc +
        # print("SigC: ",sigC)
        #
        # #Aplicam semnatura pe SigC
        # f = open('mykey.pem', 'r')
        # key = RSA.import_key(f.read())
        # h = SHA256.new()
        # signatureC = pss.new(sigC).sign(h)
        # print("Signature C: ", signatureC, end='\n\n')
        #
        # #PO(Concatenam)
        # po = Sid + amount + nc + signatureC # + OrderDesc +
        # print("PO: ", po)
        # # PO<-----------------------------------------------------------




    finally:
        sb.close()

