import socket
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

# AES_key = ''.join(chr(random.randint(0, 0xFF)) for i in range(16))
# print(AES_key)

#Clientul genereaza AES Key
# = b'123456789mnjhgdf'
#key = get_random_bytes(16)
#AES_key = AES.new(key, AES.MODE_EAX)
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
        AES_key = AES.new(key, AES.MODE_CBC, iv)

        print("Random Key: ", key)
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
        sb.send(numereCardEnc)
        sb.send(validThruEnc)
        sb.send(cvv)

        # #Primim de la Merchant Sid si SgM(Sid)
        # Sid = sb.recv(16)
        # signature = sb.recv(1024)
        # print("Sid: ", Sid)
        # print("Signature:", signature)

    finally:
        sb.close()

