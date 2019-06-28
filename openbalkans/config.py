import os
import json

import yaml

from .base import PersistentData

def determine_config_path(path=None):

    if path:
        config_file = os.path.join(path, 'config')
    else:
        config_file = os.path.join(PersistentData.config_dir, 'config')

    return config_file


class Config:

    def __init__(self, path=None, config_format='json'):

        self.path = determine_config_path(path=path)

        format_functions = self._get_format_functions(config_format)
        self.encoder = format_functions['encoder']
        self.decoder = format_functions['decoder']

    def load_config(self):
        with open(self.path, 'r') as f:
            config = self.decoder(f.read())
        return config

    def _create_config(self):
        with open(self.path, 'w') as f:
            f.write(self.encoder(PersistentData.base_config))
    
    def init_config(self, force=False):

        config_dir_exist = os.path.isdir(os.path.dirname(self.path))
        config_file_exist = os.path.isfile(self.path)

        if not config_dir_exist:
            os.mkdir(self.path)
        elif config_dir_exist and not config_file_exist:
            self._create_config()
        elif config_dir_exist and config_file_exist:
            if force:
                self._create_config()
            else:
                raise OSError('config file exists')
        else:
            raise OSError('This should never happen')

    def _get_format_functions(self, fmt):

        if fmt == 'json':
            encoder = json.dumps
            decoder = json.loads
        elif fmt == 'yaml':
            encoder = yaml.dump
            decoder = yaml.load
        else:
            raise TypeError('Does not support format: %s', config_format)

        return dict(encoder=encoder, decoder=decoder)
