from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from secretshare import Secret, SecretShare, Share

def encode_secret_from_bytes(message) -> int:
    return int.from_bytes(message, 'big')

def encode_secret_from_string(message: str) -> int:
    return int.from_bytes(message.encode('utf-8'),'big')

def decode_secret_to_bytes(secret: int) -> any:
    bit_length = secret.bit_length()  # Including sign bit.
    byte_length = (bit_length + 7) // 8
    return secret.to_bytes(byte_length, 'big')

def decode_secret_to_string(secret: int) -> str:
    bit_length = secret.bit_length() + 1  # Including sign bit.
    byte_length = (bit_length + 7) // 8
    return str(secret.to_bytes(byte_length, 'big').decode('utf-8'))

# key_internal is AES-GCM-SIV and should be a bytes-type object
# keys_public are RSA usng SHA256
def fragmentKeyAndEncrypt(key_secret, keys_public, threshold: int) -> any:
    # - Check if threshold is less than the number of keys; can't split if not
    if not (threshold <= len(keys_public)) :
        return False
    
    # - Split the secret into shares
    shamir = SecretShare(threshold, len(keys_public), secret=key_secret)
    shares = shamir.split()

    # - On success, encrypt the shares using the external keys
    shares_encrypted = []
    for i, share in enumerate(shares):
        shares_encrypted.append((
            share.point,
            keys_public[i].encrypt(
                str(share.value).encode('utf-8'), 
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
        ))
    
    # - Return encrypted fragments
    return shares_encrypted

def decryptAndAssembleFragments(private_keys, fragments_encrypted, threshold: int, share_count: int) -> bytes:
    # - Decrypt fragments
    shares = []
    for i in range(len(private_keys)):
        shares.append(
            Share(
                fragments_encrypted[i][0],
                int(private_keys[i].decrypt(
                    fragments_encrypted[i][1], 
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                ).decode('utf-8'))
            )
        )

    # - Assemble fragments to bytes object (AESGCMSIV Key)
    shamir = SecretShare(threshold, share_count, shares=shares)
    secret = shamir.combine()
    return secret

def main():
    message = "This is a long message that could support a 256 bit key"
    print("input:", message)
    my_key = message.encode('utf-8')
    my_Secret = Secret(encode_secret_from_bytes(my_key))

    # - create public and private keys
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

    fragments_encrypted = fragmentKeyAndEncrypt(my_Secret, public_keys, 4)
    #print(fragments_encrypted)

    my_key_recovered = decryptAndAssembleFragments(private_keys[:4], fragments_encrypted[:4], 4, 10)

    print("recovered:", decode_secret_to_string(my_key_recovered.value))

if __name__ == "__main__":
    main()

