import logging

from botocore.auth import HmacV1Auth

logger = logging.getLogger(__name__)


class HmacV1QueryAuth(HmacV1Auth):
    """
    Generates a presigned request for s3.

    Spec from this document:

    http://docs.aws.amazon.com/AmazonS3/latest/dev/RESTAuthentication.html
    #RESTAuthenticationQueryStringAuth

    """
    DEFAULT_EXPIRES = 3600

    def __init__(self, credentials, expires=DEFAULT_EXPIRES):
        self.credentials = credentials
        self._expires = expires

    def _get_date(self):
        return str(int(int(self._expires)))

    def get_signature(self, string_to_sign):
        return self.sign_string(string_to_sign)

    def get_string_to_sign(self, method, split, headers, expires=None,
                      auth_path=None):
        if self.credentials.token:
            headers['x-amz-security-token'] = self.credentials.token
        string_to_sign = self.canonical_string(method,
                                               split,
                                               headers,
                                               auth_path=auth_path)
        return string_to_sign
