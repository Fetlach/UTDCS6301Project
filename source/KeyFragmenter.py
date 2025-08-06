from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
from secretshare import Secret, SecretShare, Share
import json

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
def fragmentKeyAndEncrypt(key_secret, shares_json, threshold: int) -> json:
    # - Check if threshold is less than the number of keys; can't split if not
    if not (threshold <= len(shares_json["public_keys"])) :
        return False
    
    # - Split the secret into shares
    shamir = SecretShare(threshold, len(shares_json["public_keys"]), secret=key_secret)
    shares = shamir.split()

    # - On success, encrypt the shares using the external keys
    # set up fields for JSON
    j_shares = []
    j_positions = []

    for i, share in enumerate(shares):
        j_positions.append(share.point)
        j_shares.append(
            serialization.load_pem_public_key(
                shares_json["public_keys"][i]
                ).encrypt(
                str(share.value).encode('utf-8'), 
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
        )

    # - Assemble JSON
    shares_json["shares"] = j_shares 
    shares_json["share_positions"] = j_positions 
    shares_json["numShares"] = len(j_shares)
    shares_json["threshold"] = threshold
    
    # - Return encrypted fragments
    return shares_json

def decryptAndAssembleFragments(shares_json: json, threshold: int, share_count: int) -> bytes:
    # - Decrypt fragments
    shares = []
    for i in range(threshold):
        shares.append(
            Share(
                shares_json["share_positions"][i],
                int(
                    serialization.load_pem_private_key(
                        shares_json["private_keys"][i],
                        password=None
                    ).decrypt(
                        shares_json["shares"][i], 
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

# - Stripped-down version of above function to offload private key decryption
def assembleFragments(shares_json: json, threshold: int, share_count: int) -> bytes:
    # - Decrypt fragments
    shares = []
    for i in range(threshold):
        shares.append(Share(shares_json["share_positions"][i], shares_json["shares"][i]))

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
        public_key = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        public_keys.append(public_key)
        private_keys.append(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()))

    # - Create json container
    shares_json = {
        "public_keys": public_keys,
        "private_keys": private_keys,
        "shares": [],
        "share_positions": [],
        "numShares": []
    }
    #print(shares_json)

    shares_json_encrypted = fragmentKeyAndEncrypt(my_Secret, shares_json, 4)

    my_key_recovered = decryptAndAssembleFragments(shares_json_encrypted, 4, shares_json_encrypted['numShares'])

    print("recovered:", decode_secret_to_string(my_key_recovered.value))

if __name__ == "__main__":
    main()

