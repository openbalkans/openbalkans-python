import os
import re

from cryptography.exceptions import InvalidKey
from cryptography.hazmat.backends import default_backend
# from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.primitives import serialization

# Warpwallet
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from .exceptions import UnsupportedKeyFormat


def generate_secret_key():
    """
    Generate a new secret key
    """

    private_key = ec.generate_private_key(
        ec.SECP384R1(),
        default_backend(),
        )

    return private_key


def private_key_to_pem(private_key, passphrase):
    """
    Store key to file using passphrase for encryption
    """

    passphrase_bytes = bytes(passphrase, 'utf8')

    serialized_private = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(
            passphrase_bytes)
    )

    return serialized_private


def private_key_to_file(private_key, key_format, key_name, path):
    """
    Store a serialized private key to file
    """

    keyfile_name = '{key_name}.{key_format}'.format(key_name)
    key_abspath = os.path.join(path, keyfile_name)
    with open(key_abspath, 'wb') as f:
        f.write(private_key)
    return True


def private_key_from_file(path, passphrase):
    """
    load key from file
    support pem only
    this should be changed to support more than
    one format using any()
    """
    key_format = os.path.basename(path).split('.')[-1]
    if not re.match(r'pem', key_format, re.IGNORECASE):
        raise UnsupportedKeyFormat(f'{key_format} is not supported')

    passphrase_bytes = bytes(passphrase, 'utf8')
    with open(path, 'r') as keyfile:
        private_key_str = keyfile.read()

    private_key = load_pem_private_key(
        private_key_str,
        passphrase_bytes,
        default_backend())

    return private_key


def generate_scrypt_key(salt, passphrase):

    salt_bytes = bytes(salt, 'utf')
    passphrase_bytes = bytes(passphrase, 'utf8')
    # Derive key
    kdf = Scrypt(salt=salt_bytes, length=32, n=2**18,
                 p=1, r=8, backend=default_backend())
    key_bytes = kdf.derive(passphrase_bytes)

    return key_bytes


def verify_scrypt_key(salt, passphrase, key_bytes):

    passphrase_bytes = bytes(passphrase, 'utf8')
    salt_bytes = bytes(salt, 'utf8')

    # Verify key
    kdf = Scrypt(salt=salt_bytes, length=32, n=2**18,
                 p=1, r=8, backend=default_backend())
    try:
        kdf.verify(passphrase_bytes, key_bytes)
    except InvalidKey:
        return False
    else:
        return True
