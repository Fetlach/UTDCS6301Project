import os
import numpy as np
from PIL import Image
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
import secrets


def image_to_numpy(file_path):
    image = Image.open(file_path)
    array = np.array(image)
    return array, image.size, image.mode


def numpy_to_image(array, size, mode):
    image = Image.fromarray(array.reshape(size[::-1], len(mode)))
    return image


def save_to_file(file_path, array, metadata):
    np.savez(file_path, array=array, metadata=metadata)  # Save compressed data (.npz)


def read_from_file(file_path):
    content = np.load(file_path)
    return content["array"], content["metadata"].item()


def main(image_path, save_path, output_path):
    array, size, mode = image_to_numpy(image_path)
    print("Original array shape:", array.shape)

    metadata = {"size": size, "mode": mode, "dtype": str(array.dtype), "shape": array.shape}
    print("Image metadata:", metadata)

    save_to_file(save_path, array=array, metadata=metadata)
    print(f"Image and metadata saved to {save_path}")

    loaded_array, loaded_metadata = read_from_file(save_path)
    print("Loaded array shape:", loaded_array.shape)
    print("Loaded metadata:", loaded_metadata)

    assert tuple(loaded_metadata["shape"]) == array.shape, "Shape mismatch after loading!"
    assert loaded_metadata["size"] == size, "Size mismatch after loading!"
    assert loaded_metadata["mode"] == mode, "Mode mismatch after loading!"

    reconstructed_image = numpy_to_image(
        loaded_array, size=loaded_metadata["size"], mode=loaded_metadata["mode"]
    )
    reconstructed_image.save(output_path)
    print(f"Reconstructed image saved to {output_path}")



