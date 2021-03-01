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

#Cheie AES pentru C si PG
key_cpg = get_random_bytes(16)
print("CPG: ", key_cpg)
AES_CPG = AES.new(key_cpg, AES.MODE_EAX)
file_out = open("AES_CPG.bin", "wb")
file_out.write(key_cpg)
file_out.close()

if __name__ == '__main__':
    #1.a) Generam cheile RSA ale clientului
    RSA_Ckey = RSA.generate(1024)

    #PUBLIC KEY RSA CLIENT
    public_key = RSA_Ckey.publickey().exportKey()
    private_key = RSA_Ckey.exportKey()

    #1.c) Cream cheia AES:
    key = get_random_bytes(16)
    AES_key = AES.new(key, AES.MODE_EAX, iv)
    #1.Criptam cheia publica RSA cu AES
    public_keyEnc = AES_key.encrypt(public_key)
    print("Random Key: ", key, end='\n\n')

    c = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    c.connect((host, port))
    try:
        #1)Primim cheia publica RSA a MERCHANTULUI si trimitem cheia publica a clientului:
        pubKM = RSA.importKey(c.recv(1024), passphrase=None) # M -> C
        c.send(public_keyEnc) # C -> M
        print("Public key:", pubKM)

        # #Criptam numerele cardului, data de expirare, cvv
        # nameOnCardEnc = AES_key.encrypt(nameOnCard)
        # numereCardEnc = AES_key.encrypt(nrCard)
        # validThruEnc = AES_key.encrypt(validThru)
        # cvvEnc = AES_key.encrypt(cvv)
        # amountEnc = AES_key.encrypt(amount)

        # Cheia AES criptata cu cea publica
        #Criptam cheia AES cu cheia publica a lui Merchant
        encryptor = PKCS1_OAEP.new(pubKM)
        encrAES = encryptor.encrypt(key)

        #1.Trimitem cheia AES criptata la Merchant
        c.sendall(encrAES)

        # Recream aceeasi cheie AES pentru criptare
        aes_key = AES.new(key, AES.MODE_EAX, AES_key.nonce)

        #Primim de la Merchant Sid si SgM(Sid) criptate
        SidEnc = c.recv(1024)
        print("Sid encrypted: ", SidEnc)

        signatureEnc = c.recv(1024)
        print("Signature encrypted:", signatureEnc, end='\n\n')

        Sid = aes_key.decrypt(SidEnc)
        print("Sid: ", Sid)

        signature = aes_key.decrypt(signatureEnc)
        print("Signature: ", signature, end='\n\n')

        #PI----------------------------------------------------------->
        #PI(concatenarea)
        pi = nameOnCard + validThru + nrCard + Sid + amount + nc + m #+ pb_key
        print("PI: ", pi)

        #Aplicam semnatura pe PI
        f = open('RSA_PrivKC.pem', 'r')
        key = RSA.import_key(f.read())
        h = SHA256.new(pi)
        SigC_PI = pss.new(key).sign(h)
        print("Signature PI: ", SigC_PI, end='\n\n')

        #Criptez pi si signaturePI cu AES
        piEnc = AES_CPG.encrypt(pi)
        signaturePIEnc = AES_CPG.encrypt(SigC_PI)
        print("PI criptat: ", piEnc)
        print("Signature PI criptat: ", signaturePIEnc)
        # PI<-----------------------------------------------------------

        #PO----------------------------------------------------------->
        #SigC(concatenarea)
        SigC_ord_sid_amound_nc = Sid + amount + nc #+ OrderDesc +
        print("SigC: ", SigC_ord_sid_amound_nc)

        #Aplicam semnatura pe SigC
        f = open('RSA_PrivKC.pem', 'r')
        key = RSA.import_key(f.read())
        h = SHA256.new(SigC_ord_sid_amound_nc)
        signatureC = pss.new(key).sign(h)
        print("Signature C: ", signatureC, end='\n\n')

        #PO(Concatenam)
        po = Sid + amount + nc + signatureC #+ OrderDesc +
        print("PO: ", po)

        # Criptam PO si SigC
        poEnc = AES_key.encrypt(po)
        print("PO criptat: ", poEnc, end='\n\n')
        SigC_ord_sid_amound_nc_ENC = AES_key.encrypt(signatureC)
        print("Signature C criptat: ", SigC_ord_sid_amound_nc_ENC, end='\n\n')
        # PO<-----------------------------------------------------------

        #dic = {Sid, amount, nc, signatureC} #+ OrderDesc +}
        #print(dic)

        # Pasul 3:Trimitem PM si PO catre M
        c.send(poEnc)
        time.sleep(0.2)
        c.send(piEnc)
        time.sleep(0.2)
        c.send(signaturePIEnc)

        pm = piEnc + SigC_ord_sid_amound_nc_ENC
        pmEnc = AES_CPG.encrypt(pm)

        #Avem poEnc, pmEnc criptate
        Pas3 = pmEnc + poEnc
        print("Pas3:", Pas3)

        #Trimitem catre merchant
        c.send(Pas3)

    finally:
        c.close()