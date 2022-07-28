import logging

from botocore.auth import HmacV1Auth, SigV4QueryAuth
from botocore.exceptions import NoCredentialsError

logger = logging.getLogger(__name__)

SIGV4_TIMESTAMP = "%Y%m%dT%H%M%SZ"
UNSIGNED_PAYLOAD = "UNSIGNED-PAYLOAD"


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

    def get_string_to_sign(self, method, split, headers, expires=None, auth_path=None):
        if self.credentials.token:
            headers["x-amz-security-token"] = self.credentials.token
        string_to_sign = self.canonical_string(method, split, headers, auth_path=auth_path)
        return string_to_sign


class S3SigV4QueryAuth(SigV4QueryAuth):
    """S3 SigV4 auth using query parameters.

    This signer will sign a request using query parameters and signature
    version 4, i.e a "presigned url" signer.

    Based off of:

    http://docs.aws.amazon.com/AmazonS3/latest/API/sigv4-query-string-auth.html

    """

    def add_auth(self, request, x_amz_date):
        if self.credentials is None:
            raise NoCredentialsError
        request.context["timestamp"] = x_amz_date
        # This could be a retry.  Make sure the previous
        # authorization header is removed first.
        self._modify_request_before_signing(request)
        canonical_request = self.canonical_request(request)
        string_to_sign = self.string_to_sign(request, canonical_request)
        signature = self.signature(string_to_sign, request)
        return signature

    def _normalize_url_path(self, path):
        # For S3, we do not normalize the path.
        return path

    def payload(self, request):
        # From the doc link above:
        # "You don't include a payload hash in the Canonical Request, because
        # when you create a presigned URL, you don't know anything about the
        # payload. Instead, you use a constant string "UNSIGNED-PAYLOAD".
        return UNSIGNED_PAYLOAD
