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


def send_message(key,socket):
    print("please type message.")
    message = str(input())
    enc_string_2=AESCipherGCM(key).encrypt(message)
    socket.send(enc_string_2)
    print("Encrypted message sent")

def receive_message(key,socket):
    data=socket.recv(4096)
    try:
        decoded=AESCipherGCM(key).decrypt(data.decode('utf-8'))
        print('Decoded string is: ' + str(decoded))
    except:
        print("Decryption failed. Attack detected")

def main():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(('localhost', 8080))
    sock.listen(5)
    print("Listening for connections...")

    conn, addr = sock.accept()

    #Key exchange
    password = pyDHE.new(16)
    shared_key = password.negotiate(conn)
    finalKey = Util.number.long_to_bytes(shared_key)
    print('Keys shared')

    while True:
        print("Waiting for client response")
        answer = conn.recv(1024).decode()
        if answer == "send":
            receive_message(finalKey,conn)
        elif answer == "receive":
            send_message(finalKey,conn)
        else:
            print("client exited. Goodbye")
            break

    conn.close()


main()