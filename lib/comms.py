import struct
import base64

from Crypto.Cipher import XOR, AES
from Crypto.Hash import SHA256

from dh import create_dh_key, calculate_dh_secret


class StealthConn(object):
    def __init__(self, conn, client=False, server=False, verbose=False):
        self.conn = conn
        self.cipher = None
        self.client = client
        self.server = server
        self.verbose = verbose
        self.initiate_session()
        self.blocksize = 32
        self.counter = 0

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
        """
        TOM -- I have changed this bit also, made it more simple. Could not get this to run.
        If you want, we can work at strengthening it by using correct AES mode
        # key encryption key
        # AES-256, might change the mode
        self.cipher = AES.new(shared_hash[:32], AES.MODE_CFB, shared_hash[32:48])
        """

        self.cipher = AES.new(shared_hash)


        #initialise a counter to prevent replay attacks
        #use the remaining bytes from the DH handshake so this value is secret
        #self.counter = int(hex(shared_hash[48:]))

        #the server will generate a random key and send it via and encrypted channel
        """ *******************    TOM CODE ********************
        if self.server:
            f = open("/dev/random", "rU")
            newkey = f.read(32)
            newiv = f.read(16)
            self.send(newkey)
            self.send(newiv)
        if self.client:
            newkey = self.recv()
            newiv = self.recv()
            **************************************************"""
        #now build the content encryption cipher
        self.cipher = AES.new(newkey, AES.MODE_CFB, newiv)


    #TODO: code to append the MAC and counter

    def send(self, data):
        if self.cipher:
            # PEZZ - using example code from http://www.codekoala.com/posts/aes-encryption-python-using-pycrypto/
            PADDING = '{'

            # pad the text to be encrypted
            pad = lambda s: s + (BLOCKSIZE - len(s) % BLOCKSIZE) * padding
            encode_aes = lambda c, s: base64.b64encode(c.encrypt(pas(s)))
            encrypted_date = encode_aes(self.cipher, data)

            #encrypted_data = self.cipher.encrypt(data)

            if self.verbose:
                print("Original data: {}".format(data))
                print("Encrypted data: {}".format(repr(encrypted_data)))
                print("Sending packet of length {}".format(len(encrypted_data)))
        else:
            encrypted_data = data

        # Encode the data's length into an unsigned two byte int ('H')
        pkt_len = struct.pack('H', len(encrypted_data))
        self.conn.sendall(pkt_len)
        self.conn.sendall(encrypted_data)


    #TODO: code to check the MAC and counter

    def recv(self):
        # Decode the data's length from an unsigned two byte int ('H')
        pkt_len_packed = self.conn.recv(struct.calcsize('H'))
        unpacked_contents = struct.unpack('H', pkt_len_packed)
        pkt_len = unpacked_contents[0]

        decode_aes = lambda c, e: c.decrypt(base64.b64decode(e)).rstrip(PADDING)

        encrypted_data = self.conn.recv(pkt_len)
        if self.cipher:
            data = decode_aes(self.cipher, encrypted_data)
            if self.verbose:
                print("Receiving packet of length {}".format(pkt_len))
                print("Encrypted data: {}".format(repr(encrypted_data)))
                print("Original data: {}".format(data))
        else:
            data = encrypted_data

        return data

    def close(self):
        self.conn.close()
