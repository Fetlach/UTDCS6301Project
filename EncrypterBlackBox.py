import cryptography
import sys
import os
from enum import Enum
from source import FileEncrypter, FileDecrypter, KeyAssembler, KeyFragmentDistributor, KeyFragmenter

# --- Safety Principles --- #
Debug_OutputGeneratedKey = False # This needs to be false for a secure run -> key should not be printed without this being true

# --- setup --- #
keyType = int

# --- Canary file setup --- #
# !!! IMPORTANT - Should be static between runs; do not modify !!!
canaryFile_Name = 'canary.txt'
canaryFile_Content = 'This canary file is unencrypted.'

# --- Canary file functions --- #
def createCanaryFile(filePath: str, encryptionKey: keyType) -> bool:
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

    # - encrypt the file; return if the operation was successful
    return FileEncrypter.encryptFile(os.path.join(filePath, canaryFile_Name), encryptionKey)

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
    key = True
    
    return key

def encryptionRoutine() -> bool:
    # - Generate our internal key
    Key_AESGCM = generateInternalKey_AESGCM()
    if (Debug_OutputGeneratedKey):
        print(Key_AESGCM)

    # - fragment our key

    # - encrypt our key fragments using provided public keys

    # - output key fragments

    # - Once key is recoverable; begin encrypting files

    # - All files encrypted, so return
    return True

# --- Decryption routine functions --- #
def decryptionRoutine() -> bool:
    # - Retrieve provided key fragments

    # - Combine key fragments into AES-GCM key

    # - On success, try to decrypt canary file

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
            pass
        case _:
            pass

    # - execution completed successfully - #
    exit()

    
