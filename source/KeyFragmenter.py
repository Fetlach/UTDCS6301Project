from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
import ShamirSecretSharing

# key_internal is AES-GCM-SIV and should be a string type
# keys_public are RSA usng SHA256
def fragmentKeyAndEncrypt(key_internal_int, keys_public, threshold_to_reconstruct: int) -> any:
    # - Check if threshold is less than the number of keys; can't split if not
    if not (threshold_to_reconstruct <= len(keys_public)) :
        return False

    # - Convert key to int for SSS implementation
    #key_internal_int = int.from_bytes(key_internal.to_bytes(), 'big')
    
    # - Try to split the key into shares
    shares = ShamirSecretSharing.make_random_shares(key_internal_int, minimum=threshold_to_reconstruct, shares=len(keys_public))
    shares_encrypted = []

    # - On success, encrypt the shares using the external keys


    for i in range(len(keys_public)):
        shares_encrypted.append(
            (i,
            keys_public[i].encrypt(
                str(shares[i][1]).encode('utf-8'), 
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            )
        )
    
    # - Return encrypted fragments
    return shares

def decryptAndAssembleFragments(private_keys, fragments_encrypted) -> any:
    # - Decrypt fragments

    # - Assemble fragments
    key_internal_int = ShamirSecretSharing.recover_secret(Fragments)
    key_internal = bytes(key_internal_int).decode(utf-8)
    return key_internal

def main():
    message = "This is a sample key. No problemos!"
    print("input:", message)
    my_key = int.from_bytes(message.encode('utf-8'), 'big')

    public_keys = []
    private_keys = []

    for i in range(10):
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        public_key = private_key.public_key()
        public_keys.append(public_key)
        private_keys.append(private_key)

    fragments_encrypted = fragmentKeyAndEncrypt(my_key, public_keys, len(public_keys) - 1)
    print(fragments_encrypted)

    my_key_recovered = decryptAndAssembleFragments(private_keys, fragments_encrypted)

    message_recovered = bytes(my_key_recovered).decode('utf-8')
    print("output:", message_recovered)

if __name__ == "__main__":
    main()

