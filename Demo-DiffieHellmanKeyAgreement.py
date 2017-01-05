import os
import base64
import hashlib


class GetSecure:

    @staticmethod
    # Much more secure random number generator
    def random_number(max_value=(2 ** 10)):

        intermediate_integer = 0
        # ^ Useful for preventing this function from returning a 0 value
        while intermediate_integer <= 0:

            # Get an array of random binary bytes
            random_seed = bytearray(os.urandom(int(max_value)))

            # Convert that array to an integer
            intermediate_integer = int.from_bytes(random_seed, byteorder='big', signed=False)

            # If the integer is negative, make it positive
            intermediate_integer *= -1 if intermediate_integer < 0 else 1

        # Return the remainder of intermediate_integer / max_value
        return intermediate_integer % max_value

    @staticmethod
    # Function for deriving an encryption key suitable for use with 256-bit AES encryption
    def encryption_key(S_k, key_size=32, iterations=2 ** 18):

        # Set up a SHA-512 hash provider
        hash_provider = hashlib.sha512()

        # Run through a few thousand iterations of the hash function to derive a key
        for i in range(0, iterations):

            # Prepare to compute the hash value of S_k
            hash_provider.update(bytearray(S_k))

            # Set the next value of S_k equal to the hash of the current value of S_k
            S_k = hash_provider.digest()

        # Encode the result of the above computation in base 64.  The result is a string comprised of this character set
            # A-Z, a-z, 0-9, +, /, =
        encryption_key = base64.b64encode(S_k)

        # Truncate the encryption key to the required key size and return it
        return encryption_key.decode('utf-8')[:key_size]


class KeyAgreementClient:

    # Set the object's internal variables to the following values on object creation
    def __init__(self, prime, generator):
        self.public_key = 0
        self.prime_number = prime
        self.generator = generator
        self.private_key = GetSecure.random_number()

    def calculate_public_key(self):
        """
            A client's public key is calculated as the remainder of the provided generator taken to the power of
             the client's private, divided by the agreed upon prime number.
        """
        self.public_key = pow(self.generator, self.private_key, self.prime_number)

    def derive_shared_secret(self, other_public_key):
        """
            The shared secret key is the remainder of each party's public key taken to the power of the other party's
              private key, then divided by the agreed upon prime number
        """
        return pow(other_public_key, self.private_key, self.prime_number)

"""

====> Start Reading Here

    - Purpose

        The Diffie-Hellman key exchange is an algorithm used for two parties to agree on an encryption key while
          eliminating the possibility of an eavesdropper ever being able to figure out the value of the key being used.

    - Summary

        This might be actual magic.  The algorithmic explanation is a bit hard to follow, it makes much more sense when
          you see it in action.  Check below the entry point for the example.

    - Implementation

        The shared key (S_k) is a result of the function S_k == (g ** a % P) ** b % P == (g ** b % P) ** a % P, where
          ** denotes exponentiation, P is a prime number, g is a primitive root modulo P, and a and b are arbitrary
          random numbers chosen by the participating clients.

        P and g can be exchanged across the network unencrypted, as can the results of the calculations (g ** a % P) and
          (g ** b % P) without allowing an eavesdropper to compute the value of S_k.  However, the arbitrary random integers
          a and b MUST NOT EVER be transmitted to ensure the security of S_k.

        Once a client has P, g, either a or b (henceforth referred to as n), and the result of the other party's calculation
          of (g ** n % P) (henceforth A), the client may derive S_k by computing (A ** n % P).  Post computation, this value
          may be converted into an encryption key of the appropriate length by using a secure hash function.

    - Notes

        I'm using a small prime/generator group for clarity.  Never, ever, ever, ever, ever use a prime number less than
          2 ** 2047 when you actually implement this algorithm in production.

"""

# Entry Point
if __name__ == "__main__":

    # Clear the console
    os.system("cls") if os.name == 'nt' else os.system("clear")

    # P is a prime number, and g is a primitive root modulo P
    P = 523
    g = 7

    print("\nThe clients have agreed to use the following: \n\tPrime number: {0}\n\tGenerator: {1}\n".format(P, g))

    # Two clients receive P and g, and pick an arbitrary random number
    ClientA = KeyAgreementClient(P, g)
    ClientB = KeyAgreementClient(P, g)
    print("Client A chose a random number: {0}\nClient B chose a random number: {1}\n".format(ClientA.private_key,
                                                                                              ClientB.private_key))

    # The clients both calculate their public keys (g ** n % P)
    ClientA.calculate_public_key()
    ClientB.calculate_public_key()
    print("Client A's public key is: {0}\nClient B's public key is: {1}\n".format(ClientA.public_key,
                                                                                  ClientB.public_key))

    # Client A sends her public key to Client B.  Client B uses Client A's public key to compute the shared secret
    B_Secret = ClientB.derive_shared_secret(ClientA.public_key)

    # Client B sends her public key to Client A.  Client A uses Client B's public key to compute the shared secret
    A_Secret = ClientA.derive_shared_secret(ClientB.public_key)

    # Both clients now share a secret integer of the exact same value
    print("Client A derived shared secret: {0}\nClient B derived shared secret: {1}\n".format(A_Secret, B_Secret))

    # These values can be used to derive a shared encryption key
    print("Client A derived encryption key: {0}\nClient B derived encryption key: {1}\n".format(
        GetSecure.encryption_key(A_Secret), GetSecure.encryption_key(B_Secret)))

    input("All operations completed.  Press Enter to exit.")
    exit(0)

"""

====> Script Output


    The clients have agreed to use the following:
            Prime number: 523
            Generator: 7

    Client A chose a random number: 100
    Client B chose a random number: 648

    Client A's public key is: 44
    Client B's public key is: 304

    Client A derived shared secret: 99
    Client B derived shared secret: 99

    Client A derived encryption key: tjN+LmYXEyTRC7yQ+WGpd9FnOWQTlMpN
    Client B derived encryption key: tjN+LmYXEyTRC7yQ+WGpd9FnOWQTlMpN

    All operations completed.  Press Enter to exit.

"""