from Crypto.Hash import SHA
from Crypto.Random import random

# Project TODO: Is this the best choice of prime? Why? Why not? Feel free to replace!

# 1536 bit safe prime for Diffie-Hellman key exchange
# obtained from RFC 3526
prime = int("0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1\
29024E088A67CC74020BBEA63B139B22514A08798E3404DD\
EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245\
E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED\
EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D\
C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F\
83655D23DCA3AD961C62F356208552BB9ED529077096966D\
670C354E4ABC9804F1746C08CA237327FFFFFFFFFFFFFFFF", 16)

print(prime)
# Convert from the value supplied in the RFC to an integer
#prime = read_hex(raw_prime)

q = 18617231704454832626265615696651172326566222819381257356022986674393764073508483447800645352287577092465504995486632657855407836554745463960276461621492731435221236734565312023296963
g = 2

# Project TODO: write the appropriate code to perform DH key exchange

def create_dh_key():
    # Creates a Diffie-Hellman key
    # Returns (public, private)
    a = random.randint(0, int(2**16))
    return (a, pow(2, a, prime))

#TODO: write function that will send a message with appropriate data

def calculate_dh_secret(their_public, my_private):
    #validate public key to protect against a small subgroup attack
    if their_public < 2 or their_public > p-1:
        print("invalid public key")
        return None
    if pow(their_public, q, prime) != 1:
        print("invalid public key")
        return None
    # Calculate the shared secret
    shared_secret = pow(their_public, my_private, prime)

    # Hash the value so that:
    # (a) There's no bias in the bits of the output
    #     (there may be bias if the shared secret is used raw)
    # (b) We can convert to raw bytes easily
    # (c) We could add additional information if we wanted
    # Feel free to change SHA256 to a different value if more appropriate
    #TOM: changed to SHA-1 to comply with RFC standard

    #oid for AES-256
    keyspecificinfo = "aes 42"
    #number of bits in AES-256 key
    supppubinfo = "00 00 01 00 "
    #first block of 160 bits, we need an additional 96 bits
    KM1 = SHA.new(bytes(shared_secret + "00 00 00 01" + keyspecificinfo + supppubinfo, "ascii")).hexdigest()
    KM2 = SHA.new(bytes(shared_sected + "00 00 00 02" + keyspecificinfo + supppubinfo, "ascii")).hexdigest()
    KM3 = SHA.new(bytes(shared_sected + "00 00 00 03" + keyspecificinfo + supppubinfo, "ascii")).hexdigest()
    #the shared hash has 60 bytes
    #we need 32 for the key and 16 more for the iv
    shared_hash = KM1 + KM2 + KM3
    return shared_hash

#TODO: write funtion that will generate AES-256 key and transmit it using KEK
