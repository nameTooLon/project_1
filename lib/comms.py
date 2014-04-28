import struct
import random

from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Hash import HMAC
from Crypto import Random

from dh import create_dh_key, calculate_dh_secret

from lib.crypto_utils import ANSI_X923_pad, ANSI_X923_unpad

class StealthConn(object):
    def __init__(self, conn, client=False, server=False, verbose=False):
        self.conn = conn
        self.cipher = None
        self.hmac = None
        self.client = client
        self.server = server
        self.verbose = verbose
        self.newiv = None
        self.key = None
        self.initiate_session()

    def initiate_session(self):
        # Perform the initial connection handshake for agreeing on a shared secret

        ### TODO: Your code here!
        # This can be broken into code run just on the server or just on the client
        if self.server or self.client:
            my_public_key, my_private_key = create_dh_key()
            # Send them our public key
            self.send(bytes(str(my_public_key), "ascii"))
            # Receive their public key
            their_public_key = int(self.recv())
            # Obtain our shared secret
            shared_hash = calculate_dh_secret(their_public_key, my_private_key)
            print("Shared hash: {}".format(shared_hash))
        # key encryption key
        # AES-256, might change the mode
        self.key = shared_hash[:32]
        print("KEY",self.key)
        self.newiv = shared_hash[32:48]
        self.cipher = AES.new(self.key, AES.MODE_CFB, self.newiv)
        self.hmac = HMAC.new(shared_hash[-16:].encode("ascii"), digestmod=SHA256)

        #initialise a counter to prevent replay attacks
        #use the remaining bytes from the DH handshake so this value is secret
        #self.counter = int(shared_hash[48:])

        # update AES cipher with new IV
        #the server will generate a random key and send it via and encrypted channel

        #now build the content encryption cipher

        # did not have time (or enough key material) to ensure proper HMAC key.
        if self.newiv:
            self.cipher = AES.new(self.key, AES.MODE_CFB, self.newiv)


    #TODO: code to append the MAC and counter

    def send(self, data):
        if self.cipher:
            self.newiv = Random.new().read(16)
            print("HERE: ", self.key, self.newiv);
            self.cipher = AES.new(self.key, AES.MODE_CFB, self.newiv)

            self.hmac.update(data)
            data = self.hmac.digest() + data
            padded_data = ANSI_X923_pad(data, 32)
            encrypted_data = self.cipher.encrypt(padded_data)
            encrypted_data = self.newiv + encrypted_data
            if self.verbose:
                print("Original data: {}".format(data))
                print("Padded data: {}".format(padded_data))
                print("Encrypted data: {}".format(repr(encrypted_data)))
                print("Sending packet of length {}".format(len(encrypted_data)))
        else:
            encrypted_data = data

        # Encode the data's length into an unsigned two byte int ('H')
        pkt_len = struct.pack(b'H', len(encrypted_data))
        self.conn.sendall(pkt_len)
        self.conn.sendall(encrypted_data)

    #TODO: code to check the MAC and counter
    def recv(self):
        # Decode the data's length from an unsigned two byte int ('H')
        pkt_len_packed = self.conn.recv(struct.calcsize('H'))
        unpacked_contents = struct.unpack(b'H', pkt_len_packed)
        pkt_len = unpacked_contents[0]

        encrypted_data = self.conn.recv(pkt_len)

        if self.cipher:
            self.newiv = encrypted_data[:16]
            self.cipher = AES.new(self.key, AES.MODE_CFB, self.newiv)
            padded_data = self.cipher.decrypt(encrypted_data[16:])
            data = ANSI_X923_unpad(padded_data, 32)
            mac = data[:32]
            data = data[32:]
            self.hmac.update(data)
            if mac == self.hmac.digest():
                print("This message has been validated")
            else:
                print("Recieved mac: {}".format(mac))
                print("Mac digest: {}".format(self.hmac.digest()))
                print("sorry dude, there is something fishy going on here")
            if self.verbose:
                print("Receiving packet of length {}".format(pkt_len))
                print("Encrypted data: {}".format(repr(encrypted_data)))
                print("Padded data: {}".format(padded_data))
                print("Original data: {}".format(data))
        else:
            data = encrypted_data

        return data

    def close(self):
        self.conn.close()
