import os
import json
from json import JSONDecodeError

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

from future.utils import raise_from

from .base import PersistentData

def generate_key():
    private_key = ec.generate_private_key(
        ec.SECP384R1(),
        default_backend(),
        )

    return private_key

def store_private_key(designation):
    pass


def get_key_files(alternate_key_dir=None):
    key_dir = alternate_key_dir or PersistentData.key_dir
    try:
        keyfile_walk = next(os.walk(key_dir))
        root, dirs, keyfiles = keyfile_walk
        key_file_list = [os.path.join(root, keyfile) for keyfile in keyfiles]
    except StopIteration:
        raise OSError('openbalkans configuration directory does not exist')
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
