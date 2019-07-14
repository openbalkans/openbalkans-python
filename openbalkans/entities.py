from .common import *


class User:

    """
    This class should represent the interface the user has with the underlying
    system. any interaction with config files, keys or data should be contained
    ain this class.
    """

    def __init__(self, designation=None):
        if designation:
            pass

    @classmethod
    def from_warp_wallet(self, passphrase, salt):
        pass

    @staticmethod
    def _get_key_by_designation(self, designation):
        pass


class Post:

    """
    This class should expose an interface for creating posts
    with default structure unless explicitly passed a template
    with which to create a post.

    Post objects should be signed by the User class
    """

    def __init__(self):
        pass

    def sign(self):
        """
        This method should accept a User instance and use it
        to sign the post
        """
