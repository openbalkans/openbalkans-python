import os
import json
import struct


from json import JSONDecodeError

import six

from cryptography.exceptions import InvalidKey
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.primitives import serialization

# Warpwallet
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from future.utils import raise_from

from .base import PersistentData


def str_to_bytes_comp(s):
    return bytes(s) if six.PY2 else bytes(s, 'utf8')

def bytes_to_str_comp(b):
    return str(b) if six.PY2 else (b, 'utf8')

def generate_private_key():

    private_key = ec.generate_private_key(
        ec.SECP384R1(),
        default_backend(),
        )

    return private_key


def private_key_to_pem(private_key, passphrase):

    passphrase_bytes = str_to_bytes_comp(passphrase)

    serialized_private = private_key.private_bytes( 
        encoding=serialization.Encoding.PEM, 
        format=serialization.PrivateFormat.PKCS8, 
        encryption_algorithm=serialization.BestAvailableEncryption(
            passphrase_bytes)
    )

    return serialized_private


def private_key_str_to_file(private_key, designation, config_dir):
    keyfile_name = '{}.pem'.format(designation)
    key_abspath = os.path.join(config_dir, keyfile_name)
    with open(key_abspath, 'wb') as f:
        f.write(private_key)
    return True


def load_key_from_file(keyfile_abspath, passphrase):
    passphrase_bytes = str_to_bytes_comp(passphrase)
    with open(keyfile_abspath, 'r') as keyfile:
        private_key_str = keyfile.read()
    private_key = load_pem_private_key(private_key_str, passphrase_bytes, default_backend())
    return private_key


def get_key_files(alternate_key_dir=None):
    key_dir = alternate_key_dir or PersistentData.config_dir
    try:
        keyfile_walk = next(os.walk(key_dir))
        root, dirs, keyfiles = keyfile_walk
        key_file_list = [os.path.join(root, keyfile) for keyfile in keyfiles]
    except StopIteration:
        raise OSError('openbalkans configuration directory does not exist or empty')
    return key_file_list


def get_private_key(designation, alternate_key_dir=None):
    keyfiles = get_key_files(alternate_key_dir=alternate_key_dir)
    for keyfile in keyfiles:
        try:
            with open(keyfile, 'r') as keyfile_object:
                key_json = json.loads(keyfile_object.read())

            return key_json[designation]
        except OSError as exc:
            raise_from(OSError('Key directory may be empty', exc))
        except JSONDecodeError as exc:
            raise_from(JSONDecodeError('A problem occured with the key file'), exc)


def generate_scrypt_key(salt, passphrase):

    salt_bytes = str_to_bytes_comp(salt)
    passphrase_bytes = str_to_bytes_comp(s=passphrase)
    # Derive key
    kdf = Scrypt(salt=salt_bytes, length=32, n=2**18,
                 p=1, r=8, backend=default_backend())
    key_bytes = kdf.derive(passphrase_bytes)

    return key_bytes


def verify_scrypt_key(salt, passphrase, key_bytes):

    passphrase_bytes = str_to_bytes_comp(passphrase)
    salt_bytes = str_to_bytes_comp(salt)

    # Verify key
    kdf = Scrypt(salt=salt_bytes, length=32, n=2**18,
                 p=1, r=8, backend=default_backend())
    try:
        kdf.verify(passphrase_bytes, key_bytes)
    except InvalidKey:
        return False
    else:
        return True
