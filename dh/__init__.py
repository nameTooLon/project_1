from Crypto.Hash import SHA256
from Crypto.Hash import HMAC
from Crypto.Random import random

from lib.helpers import read_hex

# Project TODO: Is this the best choice of prime? Why? Why not? Feel free to replace!

# PEZZ -- Changed the prime to 2048-bit MODP group (to be sure the exponent size is
# not the weakest point) (Has double the entropy of the strength of the entire system)
# 2048 bit safe prime for Diffie-Hellman key exchange
# obtained from RFC 3526
raw_prime_1536 = """FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1
      29024E08 8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD
      EF9519B3 CD3A431B 302B0A6D F25F1437 4FE1356D 6D51C245
      E485B576 625E7EC6 F44C42E9 A637ED6B 0BFF5CB6 F406B7ED
      EE386BFB 5A899FA5 AE9F2411 7C4B1FE6 49286651 ECE45B3D
      C2007CB8 A163BF05 98DA4836 1C55D39A 69163FA8 FD24CF5F
      83655D23 DCA3AD96 1C62F356 208552BB 9ED52907 7096966D
      670C354E 4ABC9804 F1746C08 CA237327 FFFFFFFF FFFFFFFF"""

raw_prime_2048 = """FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1
      29024E08 8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD
      EF9519B3 CD3A431B 302B0A6D F25F1437 4FE1356D 6D51C245
      E485B576 625E7EC6 F44C42E9 A637ED6B 0BFF5CB6 F406B7ED
      EE386BFB 5A899FA5 AE9F2411 7C4B1FE6 49286651 ECE45B3D
      C2007CB8 A163BF05 98DA4836 1C55D39A 69163FA8 FD24CF5F
      83655D23 DCA3AD96 1C62F356 208552BB 9ED52907 7096966D
      670C354E 4ABC9804 F1746C08 CA18217C 32905E46 2E36CE3B
      E39E772C 180E8603 9B2783A2 EC07A28F B5C55DF0 6F4C52C9
      DE2BCBF6 95581718 3995497C EA956AE5 15D22618 98FA0510
      15728E5A 8AACAA68 FFFFFFFF FFFFFFFF"""

# Convert from the value supplied in the RFC to an integer
prime = read_hex(raw_prime_2048)

#q = 18617231704454832626265615696651172326566222819381257356022986674393764073508483447800645352287577092465504995486632657855407836554745463960276461621492731435221236734565312023296963

#the selected generator is 2
generator = 2

# Project TODO: write the appropriate code to perform DH key exchange

def create_dh_key():
    # Creates a Diffie-Hellman key
    #ensure that randint has sufficient entropy.
    #If the value is == to 2**8, it is 100% predictible --> see lab2a
    a = random.randint(1, prime - 1)
    # Returns (public, private)
    return (pow(generator, a, prime), a)


#TODO: write function that will send a message with appropriate data

def calculate_dh_secret(their_public, my_private):
    #validate public key to protect against a small subgroup attack
    if their_public <= 1 or their_public > prime - 1:
        print("invalid public key")
        return None

    # Calculate the shared secret
    shared_secret = pow(their_public, my_private, prime)

    # Calculate the shared hash -- TOM wrote code to conform to the RFC
    # guidelines, however I could not get it working. Luke said it was
    # beyond the scope of this stage.

    # Instead, I simplified by changing the algo to SHA-1,
    # and added a salt string (hardcoded) This is not ideal in the real world.
    print(shared_secret)
    shared_sec_bytes = hex(shared_secret)
    print(shared_sec_bytes)
    shared_hash = SHA256.new(bytes(shared_sec_bytes, "ascii"))
    shared_hash.update(bytes("hardcodedSalt", "ascii"))
    return shared_hash.hexdigest()

    """
    Tom, I think that this calculation is not quite right...
    Shoudl be DIVIDE by q???  Not sure, however was not getting past
    this condition

    if pow(their_public, q, prime) != 1:
        print("invalid public key")
        return None


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
    KM1 = SHA.new(bytes(shared_secret + "00 00 00 01" + keyspecificinfo
        + supppubinfo, "ascii")).hexdigest()
    KM2 = SHA.new(bytes(shared_sected + "00 00 00 02" + keyspecificinfo
        + supppubinfo, "ascii")).hexdigest()
    KM3 = SHA.new(bytes(shared_sected + "00 00 00 03" + keyspecificinfo
        + supppubinfo, "ascii")).hexdigest()
    #the shared hash has 60 bytes
    #we need 32 for the key and 16 more for the iv
    shared_hash = KM1 + KM2 + KM3
    return shared_hash
    """

#TODO: write funtion that will generate AES-256 key and transmit it using KEK
