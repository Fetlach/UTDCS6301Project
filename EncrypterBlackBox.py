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
keyFile_Name = "log_encryption.txt"

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
    #canaryFileExists = os.path.exists(os.path.join(filePath, canaryFile_Name))
    #if (canaryFileExists):
    #    return False
    # update; we don't really care
    
    # - create and open canary file at path
    with open(os.path.join(filePath, canaryFile_Name), "w") as file:
        # - write contents
        file.write(canaryFile_Content)

        # - close the canary file

def isValidKey(filePath: str, encryptionKey: keyType) -> bool:
    # - check file exists
    fileExists = os.path.exists(filePath)
    if (not fileExists):
        return False

    # - open the file and decrypt
    encryptor = FileEncrypter.FileEncryptor(encryptionKey)
    encryptor.decrypt_file(filePath, (filePath +".tmp"))

    # - open the temp file, check if it is good
    goodCanary = False
    with open(filePath + ".tmp") as file:
        fileContents = file.read()
        goodCanary = (fileContents == canaryFile_Content)
    
    # - cleanup
    os.remove(filePath + ".tmp")

    return goodCanary

# --- Encryption routine functions --- #
# AES-GCM used internally and for resource encryption. It is a symmetric key, so do not output it anywhere in a secure run
# Users provide a list of public keys

def generateInternalKey_AESGCM() -> any:
    key = AESGCMSIV.generate_key(bit_length=256)
    return key

def encryptionRoutine(json, filepathsToEncrypt, path_output) -> bool:
    # - Generate our internal key
    newKey = generateInternalKey_AESGCM()
    Key_AESGCM = Secret(KeyFragmenter.encode_secret_from_bytes(newKey))
    if (Debug_OutputGeneratedKey):
        print(newKey)
        print(Key_AESGCM)

    # - Define expected paths
    canaryPath = os.path.join(path_output, canaryFile_Name)
    jsonPath = os.path.join(path_output, keyFile_Name)

    # - Get public rsa keys from input
    if not os.path.exists(jsonPath):
        return False
    
    shares_PublicKeysOnly = json

    # - fragment our key
    # - encrypt our key fragments using provided public keys
    shares_encrypted = KeyFragmenter.fragmentKeyAndEncrypt(Key_AESGCM, shares_PublicKeysOnly, json["threshold"])

    # --- Create metadata --- #

    # - output key fragments
    KeyFragmentDistributor.serializeJSON(jsonPath, shares_encrypted)

    # - save decryption metadata

    # - create canary file
    createCanaryFile(path_output)

    # --- Once key is recoverable; begin encrypting files --- #

    # - Create encryptor and begin encrypting
    encryptor = FileEncrypter.FileEncryptor(Key_AESGCM.to_bytes())
    #encryptor.encryptFile(canaryPath, canaryPath+".tmp")

    # - encrypt canary file
    try:
        if (encryptor.encryptFile(canaryPath, canaryPath+".tmp")): # create encrypted version in temporary file
            FileEncrypter.zero_out_file(canaryPath) # zero-out original file to eliminate non-encrypted data
            os.replace(canaryPath+".tmp", canaryPath) # then overwrite the original on success
        else: 
            print("canary failed to encrypt")
    except:
        print("canary failed to encrypt; there was a fatal error")
        return False # DO NOT ALLOW ENCRYPTION IF WE FAIL TO ADD A CANARY

    # - encrypt rest of files
    passed = False
    for f_in in filepathsToEncrypt:
        passed = False
        try:
            passed = encryptor.encryptFile(f_in, (f_in + ".tmp")) # create encrypted version in temporary file
            passed = True
        except:
            pass # recover
        if passed:
            FileEncrypter.zero_out_file(f_in) # zero-out original file to eliminate non-encrypted data
            os.replace((f_in + ".tmp"), f_in) # then overwrite the original on success

        # - Keep a log of files encrypted?

    # - All files encrypted, so return
    return True

# --- Decryption routine functions --- #
def decryptionRoutine(json, path_canary:str, filepathsToDecrypt, path_output:str) -> bool:
    # - Retrieve provided key fragments; look for log_encryption.txt in the current directory
    #shares_encrypted = KeyFragmentDistributor.deserializeJSON(currPath)

    # - Combine key fragments into AES-GCM key
    #genKey = KeyFragmenter.decryptAndAssembleFragments(json, json["threshold"], json["numShares"])
    genKey = KeyFragmenter.assembleFragments(json, json["threshold"], json["numShares"])

    # - On success, try to decrypt canary file
    # - Check if decrypted canary file contents are expected
    if not isValidKey(path_canary, genKey.to_bytes()):
        return False

    print("canary file decrypted successfully!")

    # - Continue to file decryption
    decryptor = FileEncrypter.FileEncryptor(genKey.to_bytes())
    passed = False
    for f_in in filepathsToDecrypt:
        passed = False
        try:
            passed = decryptor.decryptFile(f_in, (f_in + ".tmp")) # create encrypted version in temporary file
            passed = True
        except:
            pass # recover
        if passed:
            FileEncrypter.zero_out_file(f_in) # zero-out original file to eliminate non-encrypted data
            os.replace((f_in + ".tmp"), f_in) # then overwrite the original on success

        # - Keep a log of files decrypted?

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

class RunMode(Enum):
    NOT_PROVIDED = 1
    ENCRYPT = 2
    DECRYPT = 3

defaultJSON = {
    "public_keys": [],
    "shares": [],
    "share_positions": [],
    "numShares": 0
    "threshold": 0
}

class BlackBox_Encryption:
    path_output = "" # canary is output to this path
    json = defaultJSON
    paths_to_execute = []

    def __init__(self, path_output: str):
        self.path_output = path_output

    # - Json setup
    def loadJson(self, path: str) -> bool:
        if not os.path.exists(path):
            return False
        self.json = KeyFragmentDistributor.deserializeJSON(path)
        return True

    def addKey(self, key: bytes) -> bool:
        self.json["public_keys"] = self.json["public_keys"].append(key)
        return True

    def setThreshold(self, threshold: int) -> bool:
        if threshold < 3:
            return False
        self.json["threshold"] = threshold
        return True

    # - Routine
    def finalize_and_encrypt(self) -> bool:
        # - Check for problems
        if self.json["threshold"] < 3: 
            raise ValueError("BB_E: Threshold has to be greater than 3 to perform threshold decryption.")
            return False
        if self.json["threshold"] > len(self.json["public_keys"]):
            raise ValueError("BB_E: Threshold must be less than or equal to the number of supplied keys.")
            return False
        if not os.path.exists(self.path_output):
            raise ValueError("BB_E: Provided output path doesn't exist")
            return False

        # - Perform encryption routine
        encryptionRoutine(self.json, self.paths_to_execute, self.path_output)
        return True


class BlackBox_Decryption:
    path_output = ""
    path_canary = ""
    json = defaultJSON
    paths_to_execute = []

    def __init__(self, path_output: str, path_canary: str):
        self.path_output = path_output
        self.path_canary = path_canary

    # - Json setup
    def loadJson(self, path: str) -> bool:
        if not os.path.exists(path):
            return False
        self.json = KeyFragmentDistributor.deserializeJSON(path)
        return True

    def setNumShares(self, numShares: int) -> bool:
        if numShares < 3:
            return False
        self.json["numShares"] = numShares
        return True

    def setThreshold(self, threshold: int) -> bool:
        if threshold < 3:
            return False
        self.json["threshold"] = threshold
        return True
        
    def addShare(self, share_decrypted, position: int) -> bool:
        self.json["shares"] = self.json["shares"].append(share_decrypted)
        self.json["share_positions"] = self.json["share_positions"].append(position)
        return True

    # - Routine
    def finalize_and_decrypt(self) -> bool:
        # - Check for problems
        if self.json["threshold"] < 3: 
            raise ValueError("BB_D: Threshold has to be greater than 3 to perform threshold decryption.")
            return False
        if self.json["threshold"] > len(self.json["shares"]):
            raise ValueError("BB_D: Not enough shares were provided.")
            return False
        if not os.path.exists(self.path_output):
            raise ValueError("BB_D: Provided output path doesn't exist")
            return False
        if not os.path.exists(self.path_canary):
            raise ValueError("BB_D: Canary not found at provided path.")
            return False
        
        # Perform decryption routine
        decryptionRoutine(self.json, self.path_canary, self.paths_to_execute, self.path_output)



# --- Main --- #


if __name__ == "__main__":
    # --- Testing ---
    # - Run this to generate a list of public and private keys; the other data will be overwritten
    # serializationTest()
    # - Run this with a list of public keys to get an encrypted canary
    # encryptionRoutine(os.getcwd(), [], 4)
    # - Run this after the encryption routine and with the private keys & encoded shares to attempt to recover the canary
    # decryptionRoutine(os.getcwd())
    # exit() # - add this afterwards since the below code isn't finished

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

    
