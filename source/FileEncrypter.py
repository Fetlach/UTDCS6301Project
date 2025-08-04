from cryptography.hazmat.primitives.ciphers.aead import AESGCMSIV

# --- Types and Declarations --- #
keyType = bytes
CHUNK_SIZE = 1024 * 1024  # 1MB

# --- Number Used Once (Nonce) generator --- #
class nonceGenerator:
    def __init__(self, start=0):
        self.counter = start

    def next(self):
        if self.counter >= 2**96:
            raise ValueError("Nonce overflow: 2^96 limit reached.")
        nonce = self.counter.to_bytes(12, "big")
        self.counter += 1
        return nonce

# --- File encryptor class --- #
class FileEncryptor:
    def __init__(self, encryptionKey: bytes):
        self.aes = AESGCMSIV(encryptionKey)
        self.nonces = nonceGenerator()

    def encryptFile(self, in_path, out_path) -> bool:
        with open(in_path, 'rb') as f_in:
            with open(out_path, 'wb') as f_out:
                while chunk := f_in.read(CHUNK_SIZE):
                    nonce = self.nonce_counter.next() # nonce is stored publicly
                    ct = self.aes.encrypt(nonce, chunk, associated_data=None)
                    f_out.write(nonce + ct)  # store nonce + ciphertext

        return True
    
    def decrypt_file(self, in_path, out_path):
        with open(in_path, 'rb') as f_in:
            with open(out_path, 'wb') as fout:
                while True:
                    nonce = f_in.read(12) # nonce is stored publicly as the first 12 bytes of file
                    if not nonce:
                        break
                    ct = f_in.read(CHUNK_SIZE + 16)  # ciphertext + tag
                    pt = self.aes.decrypt(nonce, ct, associated_data=None)
                    fout.write(pt)
        return True

# --- helper functions --- #
def zero_out_file(path):
    with open(path, "r+b") as f:
        length = os.fstat(f.fileno()).st_size
        f.write(b'\x00' * length)
        f.flush()
        os.fsync(f.fileno())  # Ensure data is written