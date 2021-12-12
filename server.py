import socket
import base64
import hashlib
import pyDHE
from Crypto import Random
from Crypto.Cipher import AES
from Crypto import Util

class AESCipherGCM(object):
    def __init__(self, key): 
        self.blockSize = AES.block_size
        self.key = hashlib.sha256(key).digest()

    def _pad(self, payload):
        padSize = self.blockSize - len(payload) % self.blockSize
        return payload + chr(padSize) * padSize

    @staticmethod
    def _unpad(payload):
        #length = self.blockSize - len(payload) % self.blockSize
        #return payload[:length]
        return payload[:-ord(payload[len(payload)-1:])]

    def encrypt(self, plaintext):
        plaintext = self._pad(plaintext)
        initializationVector = Random.new().read(AES.block_size)
        # Use AES-GCM for encryption
        aes_gcm = AES.new(self.key, AES.MODE_GCM, initializationVector)
        return base64.b64encode(initializationVector + aes_gcm.encrypt(plaintext.encode()))

    def decrypt(self, ciphertext):
        ciphertext = base64.b64decode(ciphertext)
        initializationVector = ciphertext[:AES.block_size]
        aes_gcm = AES.new(self.key, AES.MODE_GCM, initializationVector)
        return self._unpad(aes_gcm.decrypt(ciphertext[AES.block_size:])).decode('utf-8')


string="This is the email"


sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.bind(('localhost', 8080))
sock.listen(5)
print("Listening for connections...")

conn, addr = sock.accept()

#Key exchange
password = pyDHE.new(16)
shared_key = password.negotiate(conn)
finalKey = Util.number.long_to_bytes(shared_key)


enc_string=str(AESCipherGCM(finalKey).encrypt(string))
enc_string_2=AESCipherGCM(finalKey).encrypt(string)
dec_string=str(AESCipherGCM(finalKey).decrypt(enc_string_2))
#print("This is the password " + password)
print("Decrypted string: " + string)
print("Encrypted string: " + enc_string)
print("Decrypted string (v2): " + str(dec_string))

conn.send(enc_string_2)

conn.close()
