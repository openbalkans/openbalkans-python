import os
import jwt
import json
import hashlib
import mimetypes
import binascii

from w3lib.url import parse_data_uri

from .encryption import generate_scrypt_key
from .exceptions import InvalidContentData, InvalidPost
from .base import UNICODE_FULL_STOP


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

    def __init__(self, post_fields, jwt_token=None):

        required_fields = [
                'openbp',
                'pk',
                'docs',
                'size',
                'type',
                'chk',
                ]

        optional_fields = [
                'other',
                'other.pk',
                'other.chk',
                'rel',
                ]

        post_field_keys = list(post_fields.keys())

        if not all(field_key in post_fields for field_key in post_field_keys):
            raise InvalidPost(
                f'not all required fields are present: {required_fields}')

        self.jwt_token = jwt_token
        self._post_fields = {k: v for k, v in post_fields.items()
                             if k in required_fields or k in optional_fields}

    def validate(self, key):
        """
        recreate the post json using stored jwt
        """

    @classmethod
    def from_json(cls, json_str):
        """
        create a post object from json string
        """
        metadata = json.loads(json_str)
        return cls(metadata)

    @classmethod
    def from_jwt(cls, jwt_str):
        """
        load, decode and validate a jwt, return post
        """
        unverified = jwt.decode(jwt_str, verify=False)
        public_key = PostKey.from_str(unverified['pk']).public_key
        jwt.decode(jwt_str, public_key, algorithm=['ES256'])
        return cls(unverified, jwt_str)

    def to_jwt(self):
        """
        return a jwt
        """
        public_key = PostKey.from_str(self._post_fields['pk']).public_key
        jwt_str = jwt.encode(self._post_fields, public_key)
        self.jwt_token = jwt_str
        return jwt_str

    def to_dict(self):
        """
        dump a json string with post data
        """

    @classmethod
    def from_content(cls, content_object,
                     public_key, urls, other=None,
                     openbp_version=None):
        """
        use a content object and public key to create a post object
        """
        # self.supported_content_types = [DataUri, FileData]

        post_content_dict = content_object.to_dict()
        post_content_dict['docs'].append(urls)

        pk = PostKey(id(post_content_dict), public_key).to_str()

        post_metadata = {
                'pk': pk,
                'openbp': openbp_version or 1,
                }

        post_metadata.update(post_content_dict)
        return cls(post_metadata)


class PostContent:

    def __init__(self, content_data, urls=None,
                 media_type=None, post_type=None):

        self.content_data = content_data
        self.media_type = media_type
        self.urls = urls if urls else list()
        self.content_type = None

        if os.path.isfile(content_data):
            self._set_data_from_file(content_data, media_type=media_type)
        else:
            self._set_data_from_data_uri(content_data, media_type=media_type)

    def _set_data_from_file(self, path, media_type=None):
        self.content_type = 'file'
        try:
            with open(path, 'rb') as f:
                contents = f.read()
        except OSError:
            raise InvalidContentData(
                    f'encountered a problem opening: {path}')

        self.size = len(contents)
        self.checksum = hashlib.sha256(contents).hexdigest()
        self.media_type = mimetypes.guess_type(path)[0] or 'text/plain'

    def _set_data_from_data_uri(self, uri, media_type=None):
        self.content_type = 'datauri'
        try:
            guessed_media_type = parse_data_uri(uri).media_type
            self.size = len(uri)
            self.checksum = hashlib.sha256(uri.encode('utf8')).hexdigest()
            self.media_type = media_type or guessed_media_type
            self.urls.append(uri)
        except ValueError:
            raise InvalidContentData(
                    f'encountered a problem parsing: {uri}')

    def to_dict(self):
        """
        This function returns a dictionary with four items
        {'size': 1, 'checksum': 'myh45h',
         'media_type': 'text/plain', 'docs': ['url1', 'url2']}
        """
        data = {
            'docs': self.urls,
            'type': self.media_type,
            'size': self.size,
            'checksum': self.checksum,
            }

        return data


class PostKey:

    def __init__(self, object_id, public_key):
        self.object_id = object_id
        self.public_key = public_key

    def to_str(self):
        object_id = str(self.object_id).encode('utf8')
        pk_bytes = object_id + UNICODE_FULL_STOP + self.public_key
        return binascii.b2a_base64(pk_bytes).decode('utf8')

    @classmethod
    def from_str(cls, pk):
        pk_data = binascii.a2b_base64(pk)
        oid, public_key = pk_data.split(UNICODE_FULL_STOP)
        return cls(int(oid.decode('utf8')), public_key)
