import base64
import copy
import datetime
import json
import logging
import re
import time
from typing import Dict, List, Tuple, TypedDict, Union
from urllib import parse as urlparse

from botocore.auth import HmacV1QueryAuth, S3SigV4QueryAuth
from botocore.awsrequest import AWSRequest, create_request_object
from botocore.compat import HTTPHeaders, urlsplit
from botocore.credentials import Credentials, ReadOnlyCredentials
from botocore.exceptions import NoCredentialsError
from botocore.utils import percent_encode_sequence
from werkzeug.datastructures import Headers, ImmutableMultiDict

from localstack import config
from localstack.aws.api import RequestContext
from localstack.aws.api.s3 import (
    AccessDenied,
    AuthorizationQueryParametersError,
    InvalidArgument,
    SignatureDoesNotMatch,
)
from localstack.aws.chain import HandlerChain
from localstack.constants import TEST_AWS_ACCESS_KEY_ID, TEST_AWS_SECRET_ACCESS_KEY
from localstack.http import Request, Response
from localstack.services.s3.utils import (
    S3_VIRTUAL_HOST_FORWARDED_HEADER,
    _create_invalid_argument_exc,
    capitalize_header_name_from_snake_case,
    uses_host_addressing,
)
from localstack.utils.strings import to_bytes

LOG = logging.getLogger(__name__)

# params are required in presigned url
SIGNATURE_V2_PARAMS = ["Signature", "Expires", "AWSAccessKeyId"]

SIGNATURE_V4_PARAMS = [
    "X-Amz-Algorithm",
    "X-Amz-Credential",
    "X-Amz-Date",
    "X-Amz-Expires",
    "X-Amz-SignedHeaders",
    "X-Amz-Signature",
]


SIGNATURE_V2_POST_FIELDS = [
    "signature",
    "AWSAccessKeyId",
]

SIGNATURE_V4_POST_FIELDS = [
    "x-amz-signature",
    "x-amz-algorithm",
    "x-amz-credential",
    "x-amz-date",
]

# headers to blacklist from request_dict.signed_headers
BLACKLISTED_HEADERS = ["X-Amz-Security-Token"]

# query params overrides for multipart upload and node sdk
# TODO: this will depends on query/post v2/v4. Manage independently
ALLOWED_QUERY_PARAMS = [
    "x-id",
    "x-amz-user-agent",
    "x-amz-content-sha256",
    "versionid",
    "uploadid",
    "partnumber",
]

IGNORED_SIGV4_HEADERS = [
    "x-id",
    "x-amz-user-agent",
    "x-amz-content-sha256",
]

FAKE_HOST_ID = "9Gjjt1m+cjU4OPvX9O9/8RuvnG41MRb/18Oux2o5H5MY7ISNTlXN+Dz9IG62/ILVxhAGI0qyPfg="

HOST_COMBINATION_REGEX = r"^(.*)(:[\d]{0,6})"
PORT_REPLACEMENT = [":80", ":443", ":%s" % config.EDGE_PORT, ""]

# STS policy expiration date format
POLICY_EXPIRATION_FORMAT1 = "%Y-%m-%dT%H:%M:%SZ"
POLICY_EXPIRATION_FORMAT2 = "%Y-%m-%dT%H:%M:%S.%fZ"


class NotValidSigV4Signature(TypedDict):
    signature_provided: str
    string_to_sign: str
    canonical_request: str


FindSigV4Result = Tuple[Union[str, None], Union[NotValidSigV4Signature, None]]


class HmacV1QueryAuthValidation(HmacV1QueryAuth):
    """
    Override _get_date for signature calculation, to use received date instead of adding a fixed Expired time
    """

    post_signature_headers = [
        header.lower()
        for header in SIGNATURE_V2_PARAMS + BLACKLISTED_HEADERS + HmacV1QueryAuth.QSAOfInterest
    ]
    QSAOfInterest_low = [qs.lower() for qs in HmacV1QueryAuth.QSAOfInterest]

    def _get_date(self):
        return str(int(self._expires))  # noqa

    def get_signature(self, method, split, headers: HTTPHeaders, expires=None, auth_path=None):
        if self.credentials.token:
            del headers["x-amz-security-token"]
            headers["x-amz-security-token"] = self.credentials.token
        string_to_sign = self.canonical_string(method, split, headers, auth_path=auth_path)
        return self.sign_string(string_to_sign), string_to_sign


class S3SigV4QueryAuthValidation(S3SigV4QueryAuth):
    """
    Override the timestamp for signature calculation, to use received timestamp instead of adding a fixed Expired time
    """

    def add_auth(self, request, timestamp):  # noqa
        if self.credentials is None:  # noqa
            raise NoCredentialsError()
        request.context["timestamp"] = timestamp
        canonical_request = self.canonical_request(request)
        string_to_sign = self.string_to_sign(request, canonical_request)
        signature = self.signature(string_to_sign, request)

        return signature, canonical_request, signature


# we are taking advantages of the fact that non-attached members are not returned
# those exceptions are polymorphic, they can have multiple shapes under the same name


def create_access_denied_headers_not_signed(headers_not_signed: str) -> AccessDenied:
    ex = AccessDenied("There were headers present in the request which were not signed")
    ex.HostId = FAKE_HOST_ID
    ex.HeadersNotSigned = headers_not_signed
    return ex


def create_access_denied_missing_parameters_sig_v2() -> AccessDenied:
    ex = AccessDenied(
        "Query-string authentication requires the Signature, Expires and AWSAccessKeyId parameters"
    )
    ex.HostId = FAKE_HOST_ID
    return ex


def create_authorization_query_parameters_error() -> AuthorizationQueryParametersError:
    ex = AuthorizationQueryParametersError(
        "Query-string authentication version 4 requires the X-Amz-Algorithm, X-Amz-Credential, X-Amz-Signature, X-Amz-Date, X-Amz-SignedHeaders, and X-Amz-Expires parameters."
    )
    ex.HostId = FAKE_HOST_ID
    return ex


def create_access_denied_expired_sig_v2(expires: float) -> AccessDenied:
    ex = AccessDenied("Request has expired")
    ex.HostId = FAKE_HOST_ID
    ex.Expires = expires
    ex.ServerTime = time.time()
    return ex


def create_access_denied_expired_sig_v4(expires: float, amz_expires: int) -> AccessDenied:
    ex = create_access_denied_expired_sig_v2(expires)
    ex.X_Amz_Expires = amz_expires
    return ex


def create_signature_does_not_match_sig_v2(
    request_signature: str, string_to_sign: str
) -> SignatureDoesNotMatch:
    ex = SignatureDoesNotMatch(
        "The request signature we calculated does not match the signature you provided. Check your key and signing method."
    )
    ex.AWSAccessKeyId = TEST_AWS_ACCESS_KEY_ID
    ex.HostId = FAKE_HOST_ID
    ex.SignatureProvided = request_signature
    ex.StringToSign = string_to_sign
    ex.StringToSignBytes = to_bytes(string_to_sign).hex(sep=" ", bytes_per_sep=2).upper()
    return ex


def create_signature_does_not_match_sig_v4(
    not_valid_sig_v4: NotValidSigV4Signature,
) -> SignatureDoesNotMatch:
    ex = create_signature_does_not_match_sig_v2(
        request_signature=not_valid_sig_v4["signature_provided"],
        string_to_sign=not_valid_sig_v4["string_to_sign"],
    )
    ex.CanonicalRequest = not_valid_sig_v4["canonical_request"]
    ex.CanonicalRequestBytes = to_bytes(ex.CanonicalRequest).hex(sep=" ", bytes_per_sep=2).upper()
    return ex


def s3_presigned_url_response_handler(_: HandlerChain, context: RequestContext, response: Response):
    """
    Pre-signed URL with PUT method (typically object upload) should return an empty body
    """
    if (
        not context.request.method == "PUT"
        or not is_presigned_url_request(context)
        or response.status_code >= 400
    ):
        return
    else:
        response.data = b""


def s3_presigned_url_request_handler(_: HandlerChain, context: RequestContext, __: Response):
    """
    Handler to validate S3 presigned URL. Checks the validity of the request signature, and raises an error if
    `S3_SKIP_SIGNATURE_VALIDATION` is set to False
    """
    if context.service.service_name != "s3":
        return

    if not is_presigned_url_request(context):
        # validate headers, as some can raise ValueError in Moto
        _validate_headers_for_moto(context.request.headers)
        return
    # will raise exceptions if the url is not valid, except if S3_SKIP_SIGNATURE_VALIDATION is True
    # will still try to validate it and log if there's an error

    # We save the query args as a set to save time for lookup in validation
    query_arg_set = set(context.request.args)

    if is_valid_sig_v2(query_arg_set):
        validate_presigned_url_s3(context)

    elif is_valid_sig_v4(query_arg_set):
        validate_presigned_url_s3v4(context)

    _validate_headers_for_moto(context.request.headers)
    LOG.debug("Valid presign url.")


def is_expired(expiry_datetime: datetime.datetime):
    now_datetime = datetime.datetime.now(tz=expiry_datetime.tzinfo)
    return now_datetime > expiry_datetime


def is_presigned_url_request(context: RequestContext) -> bool:
    """
    Detects pre-signed URL from query string parameters
    Return True if any kind of presigned URL query string parameter is encountered
    :param context: the request context from the handler chain
    """
    # Detecting pre-sign url and checking signature
    query_parameters = context.request.args
    return any(p in query_parameters for p in SIGNATURE_V2_PARAMS) or any(
        p in query_parameters for p in SIGNATURE_V4_PARAMS
    )


def is_valid_sig_v2(query_args: set) -> bool:
    """
    :param query_args: a Set representing the query parameters from the presign URL request
    :raises AccessDenied: if the query contains parts of the required parameters but not all
    :return: True if the request is a valid SigV2 request, or False if no parameters are found to be related to SigV2
    """
    if any(p in query_args for p in SIGNATURE_V2_PARAMS):
        if not all(p in query_args for p in SIGNATURE_V2_PARAMS):
            LOG.info("Presign signature calculation failed")
            ex: AccessDenied = create_access_denied_missing_parameters_sig_v2()
            raise ex

        return True
    return False


def is_valid_sig_v4(query_args: set) -> bool:
    """
    :param query_args: a Set representing the query parameters from the presign URL request
    :raises AuthorizationQueryParametersError: if the query contains parts of the required parameters but not all
    :return: True if the request is a valid SigV4 request, or False if no parameters are found to be related to SigV4
    """
    if any(p in query_args for p in SIGNATURE_V4_PARAMS):
        if not all(p in query_args for p in SIGNATURE_V4_PARAMS):
            LOG.info("Presign signature calculation failed")
            ex: AuthorizationQueryParametersError = create_authorization_query_parameters_error()
            raise ex

        return True
    return False


def _get_aws_request_headers(werkzeug_headers: Headers) -> HTTPHeaders:
    """
    Converts Werkzeug headers into HTTPHeaders() needed to form an AWSRequest
    :param werkzeug_headers: Werkzeug request headers
    :return: headers in HTTPHeaders format
    """
    # Werkzeug Headers can have multiple values for the same key
    # HTTPHeaders will append automatically the values when we set it to the same key multiple times
    # see https://docs.python.org/3/library/http.client.html#httpmessage-objects
    # see https://docs.python.org/3/library/email.compat32-message.html#email.message.Message.__setitem__
    headers = HTTPHeaders()
    for key, value in werkzeug_headers.items():
        headers[key] = value

    return headers


def _create_new_request(request: Request, headers: Dict[str, str], query_string: str) -> Request:
    """
    Create a new request from an existent one, with new headers and query string
    It is easier to create a new one as the existing request has a lot of cached properties based on query_string
    :param request: the incoming pre-signed request
    :param headers: new headers used for signature calculation
    :param query_string: new query string for signature calculation
    :return: a new Request with passed headers and query_string
    """
    return Request(
        method=request.method,
        headers=headers,
        path=request.path,
        query_string=query_string,
        body=request.data,
        scheme=request.scheme,
        root_path=request.root_path,
        server=request.server,
        remote_addr=request.remote_addr,
    )


def _create_aws_request(
    context: RequestContext, request_url: str, headers: Dict[str, str]
) -> AWSRequest:
    """
    Create a new AWSRequest based on the request_url and new headers
    :param context: RequestContext
    :param request_url: the request_url used for the calculation
    :param headers: headers used for calculation
    :return: AWSRequest needed for S3SigV4QueryAuth signer
    """
    request_dict = {
        "method": context.request.method,
        "url": request_url,
        "body": b"",
        "headers": headers,
        "context": {
            "is_presign_request": True,
            "use_global_endpoint": True,
            "signing": {"bucket": context.service_request.get("Bucket")},
        },
    }
    return create_request_object(request_dict)


def _reverse_inject_signature_hmac_v1_query(context: RequestContext) -> Request:
    """
    Reverses what does HmacV1QueryAuth._inject_signature while injecting the signature in the request.
    Transforms the query string parameters in headers to recalculate the signature
    see botocore.auth.HmacV1QueryAuth._inject_signature
    :param context:
    :return:
    """

    new_headers = {}
    new_query_string_dict = {}

    for header, value in context.request.args.items():
        header_low = header.lower()
        if header_low not in HmacV1QueryAuthValidation.post_signature_headers:
            new_headers[header] = value
        elif header_low in HmacV1QueryAuthValidation.QSAOfInterest_low:
            new_query_string_dict[header] = value

    # there should not be any headers here. If there are, it means they have been added by the client
    # We should verify them, they will fail the signature except if they were part of the original request
    for header, value in context.request.headers.items():
        header_low = header.lower()
        if header_low.startswith("x-amz-") or header_low in ["content-type", "date", "content-md5"]:
            new_headers[header] = value

    # rebuild the query string
    new_query_string = percent_encode_sequence(new_query_string_dict)

    # easier to recreate the request, we would have to delete every cached property otherwise
    reversed_request = _create_new_request(
        request=context.request,
        headers=new_headers,
        query_string=new_query_string,
    )

    return reversed_request


def _prepare_request_for_sig_v4_signature(
    context: RequestContext, request_netloc: str
) -> AWSRequest:
    """
    Prepare the request and reverse what S3SigV4QueryAuth does to allow signature calculation of the request
    see botocore.auth.SigV4QueryAuth
    :param context: RequestContext
    :return: Request
    """
    request_headers = copy.copy(context.request.headers)
    # set automatically by the handler chain, we don't want that
    request_headers.pop("Authorization", None)
    signed_headers = context.request.args.get("X-Amz-SignedHeaders")

    signature_headers = {}
    if uses_host_addressing(request_headers):
        request_headers["Host"] = request_headers.pop(S3_VIRTUAL_HOST_FORWARDED_HEADER, "")
        splitted_path = context.request.path.split("/", maxsplit=2)
        path = f"/{splitted_path[-1]}"
    else:
        path = context.request.path

    not_signed_headers = []
    for header, value in request_headers.items():
        header_low = header.lower()
        if header_low.startswith("x-amz-"):
            if header_low in IGNORED_SIGV4_HEADERS:
                continue
            if header_low not in signed_headers.lower():
                not_signed_headers.append(header_low)
        if header_low in signed_headers:
            signature_headers[header_low] = value

    if not_signed_headers:
        ex: AccessDenied = create_access_denied_headers_not_signed(", ".join(not_signed_headers))
        raise ex

    new_query_string_dict = {
        arg: value for arg, value in context.request.args.items() if arg != "X-Amz-Signature"
    }
    new_query_string = percent_encode_sequence(new_query_string_dict)
    # need to set path + query string as url for aws_request
    request_url = f"{context.request.scheme}://{request_netloc}{path}?{new_query_string}"

    aws_request = _create_aws_request(context, request_url=request_url, headers=signature_headers)

    return aws_request


def validate_presigned_url_s3(context: RequestContext) -> None:
    """
    Validate the presigned URL signed with SigV2.
    :param context: RequestContext
    """
    query_parameters = context.request.args
    # todo: use the current User credentials instead? so it would not be set in stone??
    credentials = Credentials(
        access_key=TEST_AWS_ACCESS_KEY_ID,
        secret_key=TEST_AWS_SECRET_ACCESS_KEY,
        token=query_parameters.get("X-Amz-Security-Token", None),
    )
    try:
        expires = int(query_parameters["Expires"])
    except (ValueError, TypeError):
        # TODO: test this in AWS??
        raise SignatureDoesNotMatch("Expires error?")

    auth_signer = HmacV1QueryAuthValidation(credentials=credentials, expires=expires)

    pre_signature_request = _reverse_inject_signature_hmac_v1_query(context)

    split = urlsplit(pre_signature_request.url)
    headers = _get_aws_request_headers(pre_signature_request.headers)

    signature, string_to_sign = auth_signer.get_signature(
        pre_signature_request.method, split, headers, auth_path=None
    )
    # after passing through the virtual host to path proxy, the signature is parsed and `+` are replaced by space
    req_signature = context.request.args.get("Signature").replace(" ", "+")

    if not signature == req_signature:
        if config.S3_SKIP_SIGNATURE_VALIDATION:
            LOG.warning(
                "Signatures do not match, but not raising an error, as S3_SKIP_SIGNATURE_VALIDATION=1"
            )
        else:
            ex: SignatureDoesNotMatch = create_signature_does_not_match_sig_v2(
                request_signature=req_signature, string_to_sign=string_to_sign
            )
            raise ex

    # Checking whether the url is expired or not (maybe do it first?)
    if expires < time.time():
        if config.S3_SKIP_SIGNATURE_VALIDATION:
            LOG.warning(
                "Signature is expired, but not raising an error, as S3_SKIP_SIGNATURE_VALIDATION=1"
            )
        else:
            ex: AccessDenied = create_access_denied_expired_sig_v2(expires=expires)
            raise ex


def _validate_headers_for_moto(headers: Headers) -> None:
    """
    The headers can contain values that do not have the right type, and it will throw Exception when passed to Moto
    Validate them before it get passed
    :param headers: request headers
    """
    if headers.get("x-amz-content-sha256", None) == "STREAMING-AWS4-HMAC-SHA256-PAYLOAD":
        # this is sign that this is a SigV4 request, with payload encoded
        # we do not support payload encoding yet
        # moto parses it to an int, it would raise a 500
        content_length = headers.get("x-amz-decoded-content-length")
        if not content_length:
            raise SignatureDoesNotMatch('"X-Amz-Decoded-Content-Length" header is missing')
        try:
            int(content_length)
        except ValueError:
            raise SignatureDoesNotMatch('Wrong "X-Amz-Decoded-Content-Length" header')


def _get_signature_of_presigned_request_s3v4(
    context: RequestContext, request_netloc: str
) -> FindSigV4Result:
    """
    Returns the signature of the request
    :param context: RequestContext
    :param request_netloc: the host of the original request
    :return:
    """
    # if both x-amz* header and query param, InvalidRequest, conflicting -> test it
    query_parameters = context.request.args

    credentials = ReadOnlyCredentials(
        TEST_AWS_ACCESS_KEY_ID,
        TEST_AWS_SECRET_ACCESS_KEY,
        query_parameters.get("X-Amz-Security-Token", None),
    )
    region = query_parameters["X-Amz-Credential"].split("/")[2]
    expires = int(query_parameters["X-Amz-Expires"])
    signer = S3SigV4QueryAuthValidation(credentials, "s3", region, expires=expires)

    aws_request = _prepare_request_for_sig_v4_signature(context, request_netloc=request_netloc)

    signature, string_to_sign, canonical_request = signer.add_auth(  # noqa
        aws_request, query_parameters["X-Amz-Date"]
    )
    request_sig = query_parameters["X-Amz-Signature"]
    if signature == request_sig:
        return signature, None
    else:
        return None, NotValidSigV4Signature(
            signature_provided=request_sig,
            string_to_sign=string_to_sign,
            canonical_request=canonical_request,
        )


def validate_presigned_url_s3v4(context: RequestContext) -> None:
    """
    Validate the presigned URL signed with SigV2.
    :param context: RequestContext
    :return:
    """
    signature, exception = _find_valid_signature_through_ports(context)
    if not signature:
        if config.S3_SKIP_SIGNATURE_VALIDATION:
            LOG.warning(
                "Signatures do not match, but not raising an error, as S3_SKIP_SIGNATURE_VALIDATION=1"
            )
        else:
            ex: SignatureDoesNotMatch = create_signature_does_not_match_sig_v4(exception)
            raise ex

    # Checking whether the url is expired or not
    query_parameters = context.request.args
    # TODO: should maybe try/except here -> create auth params validation before checking signature, above!!
    x_amz_date = datetime.datetime.strptime(query_parameters["X-Amz-Date"], "%Y%m%dT%H%M%SZ")
    x_amz_expires = int(query_parameters["X-Amz-Expires"])
    x_amz_expires_dt = datetime.timedelta(seconds=int(query_parameters["X-Amz-Expires"]))
    expiration_time = x_amz_date + x_amz_expires_dt
    expiration_time = expiration_time.replace(tzinfo=datetime.timezone.utc)

    if is_expired(expiration_time):
        if config.S3_SKIP_SIGNATURE_VALIDATION:
            LOG.warning(
                "Signature is expired, but not raising an error, as S3_SKIP_SIGNATURE_VALIDATION=1"
            )
        else:
            ex: AccessDenied = create_access_denied_expired_sig_v4(
                expires=expiration_time.timestamp(), amz_expires=x_amz_expires
            )
            raise ex


def _find_valid_signature_through_ports(context: RequestContext) -> FindSigV4Result:
    """
    Iterate through ports to find a valid signature
    :param context:
    :return: signature of the request if valid
    """
    exception = None
    for port in PORT_REPLACEMENT:
        url = context.request.url
        if uses_host_addressing(context.request.headers):
            netloc = context.request.headers.get(S3_VIRTUAL_HOST_FORWARDED_HEADER)
        else:
            netloc = urlparse.urlparse(url).netloc
        match = re.match(HOST_COMBINATION_REGEX, netloc)
        if match and match.group(2):
            request_netloc = netloc.replace(f"{match.group(2)}", str(port))
        else:
            request_netloc = f"{netloc}:{port}"

        signature, exception = _get_signature_of_presigned_request_s3v4(context, request_netloc)
        if signature:
            return signature, None

    # Return the last values returned by the loop, not sure which one we should select
    return None, exception


def validate_post_policy(request_form: ImmutableMultiDict) -> None:
    """
    Validate the pre-signed POST with its policy contained
    For now, only validates its expiration
    SigV2: https://docs.aws.amazon.com/AmazonS3/latest/userguide/HTTPPOSTExamples.html
    SigV4: https://docs.aws.amazon.com/AmazonS3/latest/API/sigv4-authentication-HTTPPOST.html

    :param request_form: the form data contained in the pre-signed POST request
    :raises AccessDenied, SignatureDoesNotMatch
    :return: None
    """
    if not request_form.get("key"):
        ex: InvalidArgument = _create_invalid_argument_exc(
            message="Bucket POST must contain a field named 'key'.  If it is specified, please check the order of the fields.",
            name="key",
            value="",
            host_id=FAKE_HOST_ID,
        )
        raise ex

    if not (policy := request_form.get("policy")):
        # A POST request needs a policy except if the bucket is publicly writable
        return

    # TODO: this does validation of fields only for now
    is_v4 = _is_match_with_signature_fields(request_form, SIGNATURE_V4_POST_FIELDS)
    is_v2 = _is_match_with_signature_fields(request_form, SIGNATURE_V2_POST_FIELDS)
    if not is_v2 and not is_v4:
        ex: AccessDenied = AccessDenied("Access Denied")
        ex.HostId = FAKE_HOST_ID
        raise ex

    try:
        policy_decoded = json.loads(base64.b64decode(policy).decode("utf-8"))
    except ValueError:
        # this means the policy has been tampered with
        signature = request_form.get("signature") if is_v2 else request_form.get("x-amz-signature")
        ex: SignatureDoesNotMatch = create_signature_does_not_match_sig_v2(
            request_signature=signature,
            string_to_sign=policy,
        )
        raise ex

    if expiration := policy_decoded.get("expiration"):
        if is_expired(_parse_policy_expiration_date(expiration)):
            ex: AccessDenied = AccessDenied("Invalid according to Policy: Policy expired.")
            ex.HostId = FAKE_HOST_ID
            raise ex

    # TODO: validate the signature
    # TODO: validate the request according to the policy


def _parse_policy_expiration_date(expiration_string: str) -> datetime.datetime:
    """
    Parses the Policy Expiration datetime string
    :param expiration_string: a policy expiration string, can be of 2 format: `2007-12-01T12:00:00.000Z` or
    `2007-12-01T12:00:00Z`
    :return: a datetime object representing the expiration datetime
    """
    try:
        dt = datetime.datetime.strptime(expiration_string, POLICY_EXPIRATION_FORMAT1)
    except Exception:
        dt = datetime.datetime.strptime(expiration_string, POLICY_EXPIRATION_FORMAT2)

    # both date formats assume a UTC timezone ('Z' suffix), but it's not parsed as tzinfo into the datetime object
    dt = dt.replace(tzinfo=datetime.timezone.utc)
    return dt


def _is_match_with_signature_fields(
    request_form: ImmutableMultiDict, signature_fields: List[str]
) -> bool:
    """
    Checks if the form contains at least one of the required fields passed in `signature_fields`
    If it contains at least one field, validates it contains all of them or raises InvalidArgument
    :param request_form: ImmutableMultiDict: the pre-signed POST request form
    :param signature_fields: the field we want to validate against
    :raises InvalidArgument
    :return: False if none of the fields are present, or True if it does
    """
    if any(p in request_form for p in signature_fields):
        for p in signature_fields:
            if p not in request_form:
                LOG.info("POST pre-sign missing fields")
                argument_name = capitalize_header_name_from_snake_case(p) if "-" in p else p
                ex: InvalidArgument = _create_invalid_argument_exc(
                    message=f"Bucket POST must contain a field named '{argument_name}'.  If it is specified, please check the order of the fields.",
                    name=argument_name,
                    value="",
                    host_id=FAKE_HOST_ID,
                )
                raise ex

        return True
    return False
