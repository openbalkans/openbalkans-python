import os


class PersistentData:

    key_dir = os.path.join(os.getenv('HOME', '/root'), '.openbalkans')
