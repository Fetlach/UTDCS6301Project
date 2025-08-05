import os
import numpy as np
from PIL import Image
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
import secrets


def image_to_numpy(file_path):
    """Convert image file to NumPy array."""
    image = Image.open(file_path)
    array = np.array(image)
    return array, image.size, image.mode


def numpy_to_image(array, size, mode):
    """Convert NumPy array back to image."""
    image = Image.fromarray(array.reshape(size[::-1], len(mode)))
    return image


def encrypt_array(array, key, nonce):
    """Encrypt NumPy array using AES-GCM."""
    array_bytes = array.tobytes()  # Flatten image data into raw bytes

    aes_gcm = Cipher(
        algorithms.AES(key), 
        modes.GCM(nonce), 
        backend=default_backend()
    ).encryptor()

    encrypted_data = aes_gcm.update(array_bytes) + aes_gcm.finalize()
    tag = aes_gcm.tag  # Retrieve GCM authentication tag

    return encrypted_data, tag


def decrypt_array(encrypted_data, tag, key, nonce, original_shape, dtype):
    """Decrypt AES-GCM data back to NumPy array."""
    aes_gcm = Cipher(
        algorithms.AES(key), 
        modes.GCM(nonce, tag), 
        backend=default_backend()
    ).decryptor()
    
    decrypted_data = aes_gcm.update(encrypted_data) + aes_gcm.finalize()
    return np.frombuffer(decrypted_data, dtype=dtype).reshape(original_shape)


def save_to_file(file_path, data, metadata):
    """Save data and metadata to disk."""
    np.savez(file_path, data=data, metadata=metadata)  # Save as compressed file (.npz)


def read_from_file(file_path):
    """Read data and metadata from disk."""
    content = np.load(file_path)
    return content["data"], content["metadata"].item()


# Example Workflow
def main(image_path, encrypted_save_path, decrypted_save_path):
    # Step 1: Load image data
    array, size, mode = image_to_numpy(image_path)
    print("Original array shape:", array.shape)

    # Encryption Key Setup
    password = b"supersecretpassword"
    salt = secrets.token_bytes(16)  # Generate random salt
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = kdf.derive(password)  # Generate encryption key from password
    nonce = secrets.token_bytes(12)  # Generate random 12-byte nonce (IV)

    # Step 2: Encrypt image data
    encrypted_data, tag = encrypt_array(array, key, nonce)
    metadata = {
        "size": size,
        "mode": mode,
        "dtype": str(array.dtype),
        "shape": array.shape,
        "tag": tag,
        "nonce": nonce,
        "salt": salt,
    }
    print("Encrypted data size:", len(encrypted_data))

    # Save encrypted data
    save_to_file(encrypted_save_path, encrypted_data, metadata)
    print(f"Encrypted file saved to {encrypted_save_path}")

    # Step 3: Read encrypted data and decrypt it later
    loaded_encrypted_data, loaded_metadata = read_from_file(encrypted_save_path)

    decrypted_array = decrypt_array(
        loaded_encrypted_data,
        loaded_metadata["tag"],
        key,
        loaded_metadata["nonce"],
        tuple(loaded_metadata["shape"]),
        np.dtype(loaded_metadata["dtype"]),
    )
    print("Decrypted array shape:", decrypted_array.shape)

    # Verify decryption and reshape into original format
    reconstructed_image = numpy_to_image(decrypted_array, size, mode)
    reconstructed_image.save(decrypted_save_path)
    print(f"Decrypted file saved to {decrypted_save_path}")


if __name__ == "__main__":
    main("example.jpg", "encrypted_file.npz", "decrypted_image.jpg")
