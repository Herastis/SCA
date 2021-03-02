import socket
import time
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA256
from Crypto.Signature import pss
import socket


host = "localhost"
port = 9009

# ----Optrional
# Customer

# ---------------------------------------------------

# Card and payment details-------
nameOnCard = b'Culai Vasile-Ion'
nrCard = b'4367110087623798'
validThru = b'09/23'  # strftime maybe
cvv = b'100'
amount = b'100$'
nc = b'03916'
m = b'MULQ3'
OrderDesc = "Cartofi moi si buni la 100$ jumatatea de kilogram"
data = bytes(OrderDesc, encoding='utf-8')
# -------------------------------
iv = b'12345678abcdefgh'

# Cheie AES pentru C si PG
key_cpg = get_random_bytes(16)
print("CPG: ", key_cpg)
AES_CPG = AES.new(key_cpg, AES.MODE_EAX)
file_out = open("AES_CPG.bin", "wb")
file_out.write(key_cpg)
file_out.close()

if __name__ == '__main__':
    # 1.a) Generam cheile RSA ale clientului
    RSA_Ckey = RSA.generate(1024)

    # PUBLIC KEY RSA CLIENT
    public_key = RSA_Ckey.publickey().exportKey()
    private_key = RSA_Ckey.exportKey()

    # 1.c) Cream cheia AES:
    key_aes = get_random_bytes(16)
    AES_CM = AES.new(key_aes, AES.MODE_EAX, iv)
    # 1.Criptam cheia publica RSA cu AES
    public_keyEnc = AES_CM.encrypt(public_key)
    print("Random Key: ", key_aes, end='\n\n')

    c = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    c.connect((host, port))
    try:
        # 1)Primim cheia publica RSA a MERCHANTULUI si trimitem cheia publica a clientului:
        pubKM = RSA.importKey(c.recv(1024), passphrase=None)  # M -> C
        c.send(public_keyEnc)  # C -> M
        print("Public key:", pubKM)

        # #Criptam numerele cardului, data de expirare, cvv
        # nameOnCardEnc = AES_key.encrypt(nameOnCard)
        # numereCardEnc = AES_key.encrypt(nrCard)
        # validThruEnc = AES_key.encrypt(validThru)
        # cvvEnc = AES_key.encrypt(cvv)
        # amountEnc = AES_key.encrypt(amount)

        # Cheia AES criptata cu cea publica
        # Criptam cheia AES cu cheia publica a lui Merchant
        encryptor = PKCS1_OAEP.new(pubKM)
        publicKey_PG = encryptor.encrypt(key_aes)

        # 1.Trimitem cheia AES criptata la Merchant
        c.sendall(publicKey_PG)

        # Recream aceeasi cheie AES pentru criptare
        aes_key = AES.new(key_aes, AES.MODE_EAX, AES_CM.nonce)

        # Primim de la Merchant Sid si SgM(Sid) criptate
        SidEnc = c.recv(1024)
        print("Sid encrypted: ", SidEnc)

        signatureEnc = c.recv(1024)
        print("Signature encrypted:", signatureEnc, end='\n\n')

        Sid = aes_key.decrypt(SidEnc)
        print("Sid: ", Sid)

        signature = aes_key.decrypt(signatureEnc)
        print("Signature: ", signature, end='\n\n')

        # PI----------------------------------------------------------->
        # PI(concatenarea)
        pi = nameOnCard + b' # ' + validThru + b' # ' + nrCard + b' # ' + Sid + b' # ' + amount + nc + m  # + pb_key
        print("PI: ", pi)

        # Aplicam semnatura pe PI
        f = open('RSA_PrivKC.pem', 'r')
        key = RSA.import_key(f.read())
        h = SHA256.new(pi)
        signaturePI = pss.new(key).sign(h)
        print("Signature PI: ", signaturePI, end='\n\n')

        # Criptez pi si signaturePI cu AES
        piEnc = AES_CPG.encrypt(pi)
        SigC_PI = AES_CPG.encrypt(signaturePI)
        print("PI criptat: ", piEnc)
        print("Signature PI criptat: ", SigC_PI)
        # PI<-----------------------------------------------------------

        # PO----------------------------------------------------------->
        signature_many = Sid + amount + nc  + data
        print("SigC: ", signature_many)

        # Aplicam semnatura pe SigC
        f = open('RSA_PrivKC.pem', 'r')
        key = RSA.import_key(f.read())
        h = SHA256.new(signature_many)
        SigC_order_sid_amount_nc = pss.new(key).sign(h)
        print("Signature C: ", SigC_order_sid_amount_nc, end='\n\n')

        # PO(Concatenam)
        po = Sid + b' # ' + amount + b' # ' + nc + b' # ' + SigC_order_sid_amount_nc + b' # ' + data
        print("PO: ", po)

        # Criptam PO si SigC
        aes_key = AES.new(key_aes, AES.MODE_EAX, AES_CM.nonce)
        poEnc = aes_key.encrypt(po)
        print("PO criptat: ", poEnc, end='\n\n')
        SigC_ord_sid_amound_nc_ENC = aes_key.encrypt(SigC_order_sid_amount_nc)
        print("Signature C criptat: ", SigC_ord_sid_amound_nc_ENC, end='\n\n')
        # PO<-----------------------------------------------------------

        # Pasul 3:Trimitem PM si PO catre M
        pm = piEnc + SigC_ord_sid_amound_nc_ENC
        pmEnc = AES_CPG.encrypt(pm)

        # Avem poEnc, pmEnc criptate


        encoded_key = open("RSA_PubKPG.pem", "rb").read()
        key = RSA.import_key(encoded_key)
        encryptor = PKCS1_OAEP.new(key)
        # Cheia AES dintre C si PG criptata cu cheia RSA public a lui PG:
        publicKey_PG = encryptor.encrypt(key_cpg)

        Pas3 = pmEnc + b' # ' + poEnc
        print("Pas3:", Pas3)

        # Semnatura pe SID
        f = open('mykey.pem', 'r')
        key = RSA.import_key(f.read())
        h = SHA256.new(Sid)
        signature = pss.new(key).sign(h)
        print("Sid:", Sid)
        print("Signature:", signature, end='\n\n')

        # Trimitem catre merchant
        c.send(Pas3)
        time.sleep(0.2)
        c.send(publicKey_PG)
    finally:
        c.close()
