from cryptography.hazmat.primitives.ciphers.aead import AESGCMSIV
import sys
import os
from enum import Enum
from source import FileEncrypter, FileDecrypter, KeyFragmentDistributor, KeyFragmenter

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

    # - open the file
    with open(filePath) as file:
        fileContents = file.read()
        try:
            f = Fernet(encryptionKey)
            # - if successful; check if the contents match the known values
            return f.decrypt(fileContents) == canaryFile_Content
        except InvalidToken:
            return False
        
    return True

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
    KeyFragmentDistributor.output(shares_encrypted)

    # - save decryption metadata

    # - create canary file
    canaryPath = os.path.join(filePath, canaryFile_Name)
    createCanaryFile(currPath, Key_AESGCM)


    # --- Once key is recoverable; begin encrypting files --- #

    # - Create encryptor and begin encrypting
    encryptor = FileEncrypter.FileEncrypter(Key_AESGCM)

    # - encrypt canary file
    try:
        if(encryptor.encryptFile(canaryPath, paths.join(canaryPath, ".tmp"))): # create encrypted version in temporary file
            FileEncrypter.zero_out_file(canaryPath) # zero-out original file to eliminate non-encrypted data
            os.replace(paths.join(canaryPath, ".tmp"), canaryPath) # then overwrite the original on success
    except:
        return False # DO NOT ALLOW ENCRYPTION IF WE FAIL TO ADD A CANARY

    # - encrypt rest of files
    passed = False
    for f_in in filepathsToEncrypt:
        try:
            passed = False
            passed = encryptor.encryptFile(f_in, paths.join(f_in, ".tmp")) # create encrypted version in temporary file
        except:
            pass # recover
        if passed:
            FileEncrypter.zero_out_file(f_in) # zero-out original file to eliminate non-encrypted data
            os.replace(paths.join(f_in, ".tmp"), f_in) # then overwrite the original on success

        # - Keep a log of files encrypted?

    # - All files encrypted, so return
    return True

# --- Decryption routine functions --- #
def decryptionRoutine() -> bool:
    # - Retrieve provided key fragments

    # - Combine key fragments into AES-GCM key
    genKey = KeyFragmenter.decryptAndAssembleFragments(keys_private, shares_encrypted, threshold, share_count_orig)

    # - On success, try to decrypt canary file
    if not isValidKey(canaryPath, genKey):
        return False

    # - Check if decrypted canary file contents are expected

    # - Continue to file decryption

    # - All files decrypted, so return
    return True

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

    
