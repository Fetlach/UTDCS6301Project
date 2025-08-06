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


def save_to_file(file_path, array, metadata):
    """Save NumPy array and metadata to disk."""
    np.savez(file_path, array=array, metadata=metadata)  # Save compressed data (.npz)


def read_from_file(file_path):
    """Load NumPy array and metadata from disk."""
    content = np.load(file_path)
    return content["array"], content["metadata"].item()


def main(image_path, save_path, output_path):
    # Step 1: Load image data and convert to NumPy array
    array, size, mode = image_to_numpy(image_path)
    print("Original array shape:", array.shape)

    # Create metadata containing size and mode information
    metadata = {"size": size, "mode": mode, "dtype": str(array.dtype), "shape": array.shape}
    print("Image metadata:", metadata)

    # Step 2: Save NumPy array and metadata to disk
    save_to_file(save_path, array=array, metadata=metadata)
    print(f"Image and metadata saved to {save_path}")

    # Step 3: Load NumPy array and metadata from disk
    loaded_array, loaded_metadata = read_from_file(save_path)
    print("Loaded array shape:", loaded_array.shape)
    print("Loaded metadata:", loaded_metadata)

    # Ensure the metadata matches
    assert tuple(loaded_metadata["shape"]) == array.shape, "Shape mismatch after loading!"
    assert loaded_metadata["size"] == size, "Size mismatch after loading!"
    assert loaded_metadata["mode"] == mode, "Mode mismatch after loading!"

    # Step 4: Convert NumPy array back to image
    reconstructed_image = numpy_to_image(
        loaded_array, size=loaded_metadata["size"], mode=loaded_metadata["mode"]
    )
    reconstructed_image.save(output_path)
    print(f"Reconstructed image saved to {output_path}")


if __name__ == "__main__":
    # Example usage
    main("example.jpg", "saved_array.npz", "reconstructed_image.jpg")
