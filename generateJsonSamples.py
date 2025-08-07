import EncrypterBlackBox
from source import FileEncrypter, KeyFragmentDistributor, KeyFragmenter
import json
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCMSIV
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
import sys
import os
from secretshare import Secret, SecretShare, Share
import base64
import keyboard

defaultJSON = {
    "public_keys": [],
    "shares": [],
    "share_positions": [],
    "numShares": 10,
    "threshold": 4
}

encryptJson = defaultJSON
decryptJson = encryptJson

if __name__ == "__main__":
    public_keys = []
    private_keys = []
    myEncryptJSON = encryptJson
    myDecryptJSON = decryptJson

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
        
    # - Store json that represents encryption method
    myEncryptJSON["public_keys"] = public_keys
    KeyFragmentDistributor.serializeJSON(os.path.join(os.getcwd(),"encryptJSON.txt"), myEncryptJSON)

    print("Public keys generated")
    print("Press 'a' to continue to black box encryption...")
    keyboard.wait('a')

    # - Now test with black boxes
    outPath = os.path.join(os.getcwd(), "testFolder")
    BB_E = EncrypterBlackBox.BlackBox_Encryption(outPath, [os.path.join(os.getcwd(), "testFolder","item.txt")a])
    BB_E.loadJson(os.path.join(os.getcwd(),"encryptJSON.txt"))
    BB_E.finalize_and_encrypt()

    print("Black box encryption finished")
    print("Press 'a' to to decrypt the shares using private keys...")
    keyboard.wait('a')

    # - This is where the encryption mode would return or start encrypting files
    shares_encrypted = KeyFragmentDistributor.deserializeJSON(os.path.join(outPath, "log_encryption.txt"))

    # - Then Decrypt shares (would be done by each user with their private key)
    #shares_bytes = [base64.b64decode(s) for s in shares_encrypted["shares"]]
    #myDecryptJSON["shares"] = shares_bytes[:myEncryptJSON["threshold"]]
    shares = []
    sharePositions = []
    for i in range(max(len(shares_encrypted["shares"]), myEncryptJSON["threshold"])):
        shares.append(serialization.load_pem_private_key(
            private_keys[i],
            password=None
            ).decrypt(
                shares_encrypted["shares"][i], 
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            ))
        sharePositions.append(shares_encrypted["share_positions"][i])

    print("Share decryption finished")
    print("Press 'a' to to recover the key and decrypt the files...")
    keyboard.wait('a')
        
    myDecryptJSON["shares"] = shares
    myDecryptJSON["share_positions"] = sharePositions
    
    KeyFragmentDistributor.serializeJSON(os.path.join(os.getcwd(),"decryptJSON.txt"), myDecryptJSON)

    BB_D = EncrypterBlackBox.BlackBox_Decryption(outPath, os.path.join(outPath, "canary.txt"), [os.path.join(os.getcwd(), "testFolder","item.txt")])
    BB_D.loadJson(os.path.join(os.getcwd(),"decryptJSON.txt"))
    BB_D.finalize_and_decrypt()
