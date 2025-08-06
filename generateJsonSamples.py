import EncrypterBlackBox

defaultJSON = {
    "public_keys": [],
    "shares": [],
    "share_positions": [],
    "numShares": 10
    "threshold": 4
}

encryptJson = defaultJSON
decryptJson = defaultJSON

if __name__ == "__main__":
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

    newKey = generateInternalKey_AESGCM()
    Key_AESGCM = Secret(KeyFragmenter.encode_secret_from_bytes(newKey))

    KeyFragmentDistributor.serializeJSON(os.path.join(os.getcwd(),"encryptJSON.txt"), encryptJSON)
    KeyFragmentDistributor.serializeJSON(os.path.join(os.getcwd(),"decryptJSON.txt"), encryptJSON)
