import socket
import time
from Cryptodome.PublicKey import RSA
from Cryptodome.Cipher import PKCS1_OAEP
from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes


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

#Card details
nameOnCard = b'Culai Vasile-Ion'
nrCard = b'4367110087623798'
validThru = b'09/23           ' #strftime maybe
cvv = b'100             '

iv = b'12345678abcdefgh'

if __name__ == '__main__':
    public, private = key_generator()
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
        #aes_key = AES.new(encrAES, AES.MODE_EAX, AES_key.nonce)

        #Primim de la Merchant Sid si SgM(Sid) criptate
        SidEnc = sb.recv(1024)
        print("Sid encrypted: ", SidEnc)

        signatureEnc = sb.recv(1024)
        print("Signature encrypted:", signatureEnc)


        # Sid = aes_key.decrypt(SidEnc)
        # print("Sid: ", Sid, '\n\n')
        #
        # signature = aes_key.decrypt(signatureEnc)
        # print("Signature: ", signature, '\n\n')

    finally:
        sb.close()

