from cryptography.hazmat.primitives.ciphers.aead import AESGCMSIV
import sys
import os
import json
from enum import Enum
from source import FileEncrypter, KeyFragmentDistributor, KeyFragmenter

# temporary includes
from cryptography.hazmat.primitives import serialization
from secretshare import Secret, SecretShare, Share
from cryptography.hazmat.primitives.asymmetric import rsa

# --- References --- #


# --- Safety Principles --- #
Debug_OutputGeneratedKey = False # This needs to be false for a secure run -> key should not be printed without this being true

# --- setup --- #
keyType = int

# --- Canary file setup --- #
# !!! IMPORTANT - Should be static between runs; do not modify !!!
canaryFile_Name = 'canary.txt'
canaryFile_Content = 'This canary file is unencrypted.'

# --- Canary file functions --- #
def createCanaryFile(filePath: str) -> bool:
    # - check if file path exists
    filePathExists = os.path.exists(filePath)
    if (not filePathExists):
        return False
    
    # - check if canary file already exists at location
    canaryFileExists = os.path.exists(os.path.join(filePath, canaryFile_Name))
    if (canaryFileExists):
        return False
    
    # - create and open canary file at path
    with open(os.path.join(filePath, canaryFile_Name), "wb") as file:
        # - write contents
        file.write(canaryFile_Content)

        # - close the canary file

def isValidKey(filePath: str, encryptionKey: keyType) -> bool:
    # - check file exists
    fileExists = False
    if (not fileExists):
        return False

    # - open the file and decrypt
    encryptor = FileEncrypter.FileEncryptor(encryptionKey)
    encryptor.decrypt_file(filePath, os.path.join(filePath, ".tmp"))

    # - open the temp file, check if it is good
    goodCanary = False
    with os.path.join(filePath, ".tmp") as file:
        fileContents = file.read()
        goodCanary = (fileContents == canaryFile_Content)
    
    # - cleanup
    os.remove(os.path.join(filePath, ".tmp"))

    return goodCanary

# --- Encryption routine functions --- #
# AES-GCM used internally and for resource encryption. It is a symmetric key, so do not output it anywhere in a secure run
# Users provide a list of public keys

def generateInternalKey_AESGCM() -> any:
    key = AESGCMSIV.generate_key(bit_length=256)
    return key

def encryptionRoutine(currPath, filepathsToEncrypt, keys_public, threshold: int) -> bool:
    # - Generate our internal key
    Key_AESGCM = generateInternalKey_AESGCM()
    if (Debug_OutputGeneratedKey):
        print(Key_AESGCM)

    # - Get public rsa keys from input

    # - fragment our key
    # - encrypt our key fragments using provided public keys
    shares_encrypted = KeyFragmenter.fragmentKeyAndEncrypt(Key_AESGCM, keys_public, threshold)


    # --- Create metadata --- #

    # - output key fragments
    KeyFragmentDistributor.output(currPath, shares_encrypted)

    # - save decryption metadata

    # - create canary file
    canaryPath = os.path.join(currPath, canaryFile_Name)
    createCanaryFile(currPath, Key_AESGCM)


    # --- Once key is recoverable; begin encrypting files --- #

    # - Create encryptor and begin encrypting
    encryptor = FileEncrypter.FileEncrypter(Key_AESGCM)

    # - encrypt canary file
    try:
        if(encryptor.encryptFile(canaryPath, os.paths.join(canaryPath, ".tmp"))): # create encrypted version in temporary file
            FileEncrypter.zero_out_file(canaryPath) # zero-out original file to eliminate non-encrypted data
            os.replace(os.paths.join(canaryPath, ".tmp"), canaryPath) # then overwrite the original on success
    except:
        return False # DO NOT ALLOW ENCRYPTION IF WE FAIL TO ADD A CANARY

    # - encrypt rest of files
    passed = False
    for f_in in filepathsToEncrypt:
        try:
            passed = False
            passed = encryptor.encryptFile(f_in, os.paths.join(f_in, ".tmp")) # create encrypted version in temporary file
        except:
            pass # recover
        if passed:
            FileEncrypter.zero_out_file(f_in) # zero-out original file to eliminate non-encrypted data
            os.replace(paths.join(f_in, ".tmp"), f_in) # then overwrite the original on success

        # - Keep a log of files encrypted?

    # - All files encrypted, so return
    return True

# --- Decryption routine functions --- #
def decryptionRoutine(currPath) -> bool:
    # - Retrieve provided key fragments; look for log_encryption.txt in the current directory

    # - Combine key fragments into AES-GCM key
    genKey = KeyFragmenter.decryptAndAssembleFragments(keys_private, shares_encrypted, threshold, share_count_orig)

    # - On success, try to decrypt canary file
    if not isValidKey(canaryPath, genKey):
        return False

    # - Check if decrypted canary file contents are expected

    # - Continue to file decryption

    # - All files decrypted, so return
    return True

def serializationTest() :
    message = "This is a long message that could support a 256 bit key"
    print("input:", message)
    my_key = message.encode('utf-8')
    my_Secret = Secret(KeyFragmenter.encode_secret_from_bytes(my_key))

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

    shares_json_encrypted = KeyFragmenter.fragmentKeyAndEncrypt(my_Secret, shares_json, 4)
    KeyFragmentDistributor.serializeJSON(os.getcwd(), shares_encrypted=shares_json_encrypted)
    print("log written to:", os.getcwd())
    exit()

def deserializationTest():
    recovered = KeyFragmentDistributor.deserializeJSON(os.getcwd())
    my_key_recovered = KeyFragmenter.decryptAndAssembleFragments(recovered, 4, recovered["numShares"])
    print("recovered:", KeyFragmenter.decode_secret_to_string(my_key_recovered.value))
    exit()

# --- Main --- #
class RunMode(Enum):
    NOT_PROVIDED = 1
    ENCRYPT = 2
    DECRYPT = 3

if __name__ == "__main__":
    # - Determine running mode from commandline arguments - #
    mode = RunMode.NOT_PROVIDED
    if (len(sys.argv) < 1):
        print("Not enough arguments provided. Correct argument syntax: [ExecutionMode (e/d)]")
        exit()
    if (sys.argv == 'e'):
        mode = RunMode.ENCRYPT
    if (sys.argv == 'd'):
        mode = RunMode.DECRYPT
    # check if mode was provided
    if (mode == RunMode.NOT_PROVIDED):
        print("Execution mode could not be determined. Correct argument syntax: [ExecutionMode (e/d)]")
    
    # - Switch routines based on execution mode - #
    match mode:
        case RunMode.ENCRYPT:
            encryptionRoutine()
        case RunMode.DECRYPT:
            decryptionRoutine()
            pass
        case _:
            pass

    # - execution completed successfully - #
    exit()

    
