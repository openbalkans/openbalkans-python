import os
import json
from json import JSONDecodeError

from .base import PersistentData


def get_key_files(alternate_key_dir=None):
    key_dir = alternate_key_dir or PersistentData.config_dir
    try:
        keyfile_walk = next(os.walk(key_dir))
        root, dirs, keyfiles = keyfile_walk
        key_file_list = [os.path.join(root, keyfile) for keyfile in keyfiles]
    except StopIteration:
        raise OSError("No configuration file found")
    return key_file_list


def get_private_key(designation, alternate_key_dir=None):
    keyfiles = get_key_files(alternate_key_dir=alternate_key_dir)
    for keyfile in keyfiles:
        try:
            with open(keyfile, 'r') as keyfile_object:
                key_json = json.loads(keyfile_object.read())

            return key_json[designation]
        except OSError as exc:
            raise OSError('Key directory may be empty', exc)
        except JSONDecodeError:
            raise JSONDecodeError('A problem occured with the key file')
