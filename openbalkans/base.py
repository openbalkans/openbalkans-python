import os


class PersistentData:

    config_dir = os.path.join(os.getenv('HOME', '/root'), '.openbalkans')
    base_config = dict(
        encryption_type='ECDSA',
        )
