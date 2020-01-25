import jwt
import hashlib
import mimetypes

from w3lib.url import parse_data_uri

from .encryption import generate_scrypt_key
from .exceptions import InvalidPostData


class User:

    """
    This class should represent the interface the user has with the underlying
    system. any interaction with config files, keys or data should be contained
    ain this class.
    """

    def __init__(self, key_file=None, salt=None, passphrase=None):
        self.key = self._generate_key(key_file, salt, passphrase)

    def _generate_key(self, key_file, salt, passphrase):
        if key_file:
            pass
        elif salt and passphrase:
            return generate_scrypt_key(salt, passphrase)

    def sign_post(self, post):
        post_jwt = self._sign(post)

        return post.set_token(post_jwt)

    @classmethod
    def with_warp_wallet(cls, passphrase, salt):
        obj = cls(passphrase=passphrase, salt=salt)
        return obj

    @classmethod
    def from_key_file(cls, key_file, passphrase):
        obj = cls(key_file=key_file, passphrase=passphrase)
        return obj

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

    def __init__(
            self, public_key, material=None,
            media_type=None, other=None, *urls
            ):

        self.urls = list(urls)
        self.openbp_version = 1
        self.supported_content_types = [DataUri, FileData]

        post_data_obj = self.get_data(material, media_type)
        post_data = post_data_obj.dump()

        if material and (not urls) and (
                post_data_obj.content_type != 'datauri'):
            raise InvalidPostData('Cannot supply file path without uri')

        if post_data_obj.content_type == 'datauri':
            self.urls.append(material)

        self.public_key = public_key
        self.content = self.urls
        self.size = post_data['size']
        self.checksum = post_data['checksum']
        self.media_type = post_data['type']
        self.post_key = '0x2e' + self.public_key  # Placeholder

    def get_data(self, address, media_type=None):
        for data_type in self.supported_content_types:
            try:
                return data_type(address, media_type=media_type)
            except InvalidPostData:
                pass
        else:
            raise InvalidPostData

    def dumps(self):
        """
        This method should accept a User instance and use it
        to sign the post
        """
        data = {
            'size': self.size,
            'docs': self.content,
            'chk': self.checksum,
            'type': self.media_type,
            'openbp': self.openbp_version,
            'pk': self.post_key
            }
        return data

    def sign(self):
        json_data = self.dumps()
        jwt_data = jwt.encode(json_data, self.public_key, algorithm='ES256')
        return jwt_data


class PostData:

    def dump(self):
        """
        This function returns a dictionary with three items
        {'size': 1, 'checksum': 'myh45h', 'media_type': 'text/plain'}
        """
        data = {
            'type': self.media_type,
            'size': self.size,
            'checksum': self.checksum,
            }

        return data


class FileData(PostData):

    def __init__(self, path, media_type=None):

        try:
            self.content_type = 'file'
            with open(path, 'rb') as f:
                contents = f.read()
        except OSError:
            raise InvalidPostData(f'File does not exist: {path}')

        self.size = len(contents)
        self.checksum = hashlib.sha256(contents).hexdigest()
        self.media_type = mimetypes.guess_type(path)[0] or 'text/plain'


class DataUri(PostData):

    def __init__(self, uri, media_type=None):
        try:
            self.content_type = 'datauri'
            self.size = len(uri)
            self.checksum = hashlib.sha256(uri.encode('utf8')).hexdigest()
            self.media_type = media_type or parse_data_uri(uri).media_type
        except ValueError:
            raise InvalidPostData(uri)
