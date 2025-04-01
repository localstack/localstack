import base64
import copy
import datetime
import json
import logging
import re
import time
from collections import namedtuple
from functools import cache, cached_property
from typing import Mapping, Optional, TypedDict
from urllib import parse as urlparse

from botocore.auth import HmacV1QueryAuth, S3SigV4QueryAuth
from botocore.awsrequest import AWSRequest, create_request_object
from botocore.compat import HTTPHeaders, urlsplit
from botocore.credentials import Credentials, ReadOnlyCredentials
from botocore.exceptions import NoCredentialsError
from botocore.model import ServiceModel
from botocore.utils import percent_encode_sequence
from werkzeug.datastructures import Headers, ImmutableMultiDict

from localstack import config
from localstack.aws.accounts import get_account_id_from_access_key_id
from localstack.aws.api import CommonServiceException, RequestContext
from localstack.aws.api.s3 import (
    AccessDenied,
    AuthorizationQueryParametersError,
    EntityTooLarge,
    EntityTooSmall,
    InvalidArgument,
    InvalidBucketName,
    SignatureDoesNotMatch,
)
from localstack.aws.chain import HandlerChain
from localstack.aws.protocol.op_router import RestServiceOperationRouter
from localstack.aws.spec import get_service_catalog
from localstack.http import Request, Response
from localstack.http.request import get_raw_path
from localstack.services.s3.constants import (
    DEFAULT_PRE_SIGNED_ACCESS_KEY_ID,
    DEFAULT_PRE_SIGNED_SECRET_ACCESS_KEY,
    SIGNATURE_V2_PARAMS,
    SIGNATURE_V4_PARAMS,
)
from localstack.services.s3.utils import (
    S3_VIRTUAL_HOST_FORWARDED_HEADER,
    _create_invalid_argument_exc,
    capitalize_header_name_from_snake_case,
    extract_bucket_name_and_key_from_headers_and_path,
    forwarded_from_virtual_host_addressed_request,
    is_bucket_name_valid,
    is_presigned_url_request,
    uses_host_addressing,
)
from localstack.utils.aws.arns import get_partition
from localstack.utils.strings import to_bytes

LOG = logging.getLogger(__name__)


SIGNATURE_V2_POST_FIELDS = [
    "signature",
    "awsaccesskeyid",
]

SIGNATURE_V4_POST_FIELDS = [
    "x-amz-signature",
    "x-amz-algorithm",
    "x-amz-credential",
    "x-amz-date",
]

# headers to blacklist from request_dict.signed_headers
BLACKLISTED_HEADERS = ["X-Amz-Security-Token"]

IGNORED_SIGV4_HEADERS = [
    "x-amz-content-sha256",
]

FAKE_HOST_ID = "9Gjjt1m+cjU4OPvX9O9/8RuvnG41MRb/18Oux2o5H5MY7ISNTlXN+Dz9IG62/ILVxhAGI0qyPfg="

HOST_COMBINATION_REGEX = r"^(.*)(:[\d]{0,6})"
PORT_REPLACEMENT = [":80", ":443", f":{config.GATEWAY_LISTEN[0].port}", ""]

# STS policy expiration date format
POLICY_EXPIRATION_FORMAT1 = "%Y-%m-%dT%H:%M:%SZ"
POLICY_EXPIRATION_FORMAT2 = "%Y-%m-%dT%H:%M:%S.%fZ"

PreSignedCredentials = namedtuple(
    "PreSignedCredentials", ["access_key_id", "secret_access_key", "security_token"]
)


class NotValidSigV4SignatureContext(TypedDict):
    signature_provided: str
    string_to_sign: str
    canonical_request: str


FindSigV4Result = tuple["S3SigV4SignatureContext", Optional[NotValidSigV4SignatureContext]]


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

    def add_auth(self, request) -> tuple[bytes, str, str]:
        if self.credentials is None:  # noqa
            raise NoCredentialsError()
        canonical_request = self.canonical_request(request)
        string_to_sign = self.string_to_sign(request, canonical_request)
        signature = self.signature(string_to_sign, request)

        return signature, canonical_request, string_to_sign


# we are taking advantages of the fact that non-attached members are not returned
# those exceptions are polymorphic, they can have multiple shapes under the same name


def create_signature_does_not_match_sig_v2(
    request_signature: str, string_to_sign: str, access_key_id: str
) -> SignatureDoesNotMatch:
    ex = SignatureDoesNotMatch(
        "The request signature we calculated does not match the signature you provided. Check your key and signing method."
    )
    ex.AWSAccessKeyId = access_key_id
    ex.HostId = FAKE_HOST_ID
    ex.SignatureProvided = request_signature
    ex.StringToSign = string_to_sign
    ex.StringToSignBytes = to_bytes(string_to_sign).hex(sep=" ", bytes_per_sep=2).upper()
    return ex


def create_signature_does_not_match_sig_v4(
    not_valid_sig_v4: NotValidSigV4SignatureContext, access_key_id: str
) -> SignatureDoesNotMatch:
    ex = create_signature_does_not_match_sig_v2(
        request_signature=not_valid_sig_v4["signature_provided"],
        string_to_sign=not_valid_sig_v4["string_to_sign"],
        access_key_id=access_key_id,
    )
    ex.CanonicalRequest = not_valid_sig_v4["canonical_request"]
    ex.CanonicalRequestBytes = to_bytes(ex.CanonicalRequest).hex(sep=" ", bytes_per_sep=2).upper()
    return ex


class S3PreSignedURLRequestHandler:
    @cached_property
    def _service(self) -> ServiceModel:
        return get_service_catalog().get("s3")

    @cached_property
    def _s3_op_router(self) -> RestServiceOperationRouter:
        return RestServiceOperationRouter(self._service)

    def __call__(self, _: HandlerChain, context: RequestContext, __: Response):
        """
        Handler to validate S3 pre-signed URL. Checks the validity of the request signature, and raises an error if
        `S3_SKIP_SIGNATURE_VALIDATION` is set to False
        """
        if not context.service or context.service.service_name != "s3":
            return
        try:
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
            # TODO: set the Authorization with the data from the pre-signed query string

        except Exception:
            # as we are raising before the ServiceRequestParser, we need to
            context.service = self._service
            context.operation = self._get_op_from_request(context.request)
            raise

    def _get_op_from_request(self, request: Request):
        try:
            op, _ = self._s3_op_router.match(request)
            return op
        except Exception:
            # if we can't parse the request, just set GetObject
            return self._service.operation_model("GetObject")


def get_credentials_from_parameters(parameters: dict, region: str) -> PreSignedCredentials:
    """
    Extract and retrieves the credentials from the passed signed requests parameters (can be from the query string or
    the form for POST requests)
    :param parameters:
    :return:
    """
    # This is V2 signature AccessKeyId
    if not (access_key_id := parameters.get("AWSAccessKeyId")):
        # If not present, then it is a V4 signature (casing differs between QS parameters and form)
        credential_value = parameters.get(
            "X-Amz-Credential", parameters.get("x-amz-credential", "")
        ).split("/")
        if credential_value:
            access_key_id = credential_value[0]

    if not access_key_id:
        # fallback to the hardcoded value
        access_key_id = DEFAULT_PRE_SIGNED_ACCESS_KEY_ID

    if not (secret_access_key := get_secret_access_key_from_access_key_id(access_key_id, region)):
        # if we could not retrieve the secret access key, it means the access key was not registered in LocalStack,
        # fallback to hardcoded necessary secret access key
        secret_access_key = DEFAULT_PRE_SIGNED_SECRET_ACCESS_KEY

    security_token = parameters.get("X-Amz-Security-Token", None)
    return PreSignedCredentials(access_key_id, secret_access_key, security_token)


@cache
def get_secret_access_key_from_access_key_id(access_key_id: str, region: str) -> Optional[str]:
    """
    We need to retrieve the internal secret access key in order to also sign the request on our side to validate it
    For now, we need to access Moto internals, as they are no public APIs to retrieve it for obvious reasons.
    If the AccessKey is not registered, use the default `test` value that was historically used for pre-signed URLs, in
    order to support default use cases
    :param access_key_id: the provided AccessKeyID in the Credentials parameter
    :param region: the region from the credentials
    :return: the linked secret_access_key to the access_key
    """
    try:
        from moto.iam.models import AccessKey, iam_backends
    except ImportError:
        return

    account_id = get_account_id_from_access_key_id(access_key_id)
    moto_access_key: AccessKey = iam_backends[account_id][get_partition(region)].access_keys.get(
        access_key_id
    )
    if not moto_access_key:
        return

    return moto_access_key.secret_access_key


def is_expired(expiry_datetime: datetime.datetime):
    now_datetime = datetime.datetime.now(tz=expiry_datetime.tzinfo)
    return now_datetime > expiry_datetime


def is_valid_sig_v2(query_args: set) -> bool:
    """
    :param query_args: a Set representing the query parameters from the presign URL request
    :raises AccessDenied: if the query contains parts of the required parameters but not all
    :return: True if the request is a valid SigV2 request, or False if no parameters are found to be related to SigV2
    """
    if any(p in query_args for p in SIGNATURE_V2_PARAMS):
        if not all(p in query_args for p in SIGNATURE_V2_PARAMS):
            LOG.info("Presign signature calculation failed")
            raise AccessDenied(
                "Query-string authentication requires the Signature, Expires and AWSAccessKeyId parameters",
                HostId=FAKE_HOST_ID,
            )

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
            raise AuthorizationQueryParametersError(
                "Query-string authentication version 4 requires the X-Amz-Algorithm, X-Amz-Credential, X-Amz-Signature, X-Amz-Date, X-Amz-SignedHeaders, and X-Amz-Expires parameters.",
                HostId=FAKE_HOST_ID,
            )

        return True
    return False


def validate_presigned_url_s3(context: RequestContext) -> None:
    """
    Validate the presigned URL signed with SigV2.
    :param context: RequestContext
    """
    query_parameters = context.request.args
    method = context.request.method
    credentials = get_credentials_from_parameters(query_parameters, "us-east-1")
    signing_credentials = Credentials(
        access_key=credentials.access_key_id,
        secret_key=credentials.secret_access_key,
        token=credentials.security_token,
    )
    try:
        expires = int(query_parameters["Expires"])
    except (ValueError, TypeError):
        # TODO: test this in AWS??
        raise SignatureDoesNotMatch("Expires error?")

    # Checking whether the url is expired or not
    if expires < time.time():
        if config.S3_SKIP_SIGNATURE_VALIDATION:
            LOG.warning(
                "Signature is expired, but not raising an error, as S3_SKIP_SIGNATURE_VALIDATION=1"
            )
        else:
            raise AccessDenied(
                "Request has expired", HostId=FAKE_HOST_ID, Expires=expires, ServerTime=time.time()
            )

    auth_signer = HmacV1QueryAuthValidation(credentials=signing_credentials, expires=expires)

    split_url, headers = _reverse_inject_signature_hmac_v1_query(context.request)

    signature, string_to_sign = auth_signer.get_signature(
        method, split_url, headers, auth_path=None
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
                request_signature=req_signature,
                string_to_sign=string_to_sign,
                access_key_id=credentials.access_key_id,
            )
            raise ex

    add_headers_to_original_request(context, headers)


def _reverse_inject_signature_hmac_v1_query(
    request: Request,
) -> tuple[urlparse.SplitResult, HTTPHeaders]:
    """
    Reverses what does HmacV1QueryAuth._inject_signature while injecting the signature in the request.
    Transforms the query string parameters in headers to recalculate the signature
    see botocore.auth.HmacV1QueryAuth._inject_signature
    :param request: the original request
    :return: tuple of a split result from the reversed request, and the reversed headers
    """
    new_headers = {}
    new_query_string_dict = {}

    for header, value in request.args.items():
        header_low = header.lower()
        if header_low not in HmacV1QueryAuthValidation.post_signature_headers:
            new_headers[header] = value
        elif header_low in HmacV1QueryAuthValidation.QSAOfInterest_low:
            new_query_string_dict[header] = value

    # there should not be any headers here. If there are, it means they have been added by the client
    # We should verify them, they will fail the signature except if they were part of the original request
    for header, value in request.headers.items():
        header_low = header.lower()
        if header_low.startswith("x-amz-") or header_low in ["content-type", "date", "content-md5"]:
            new_headers[header_low] = value

    # rebuild the query string
    new_query_string = percent_encode_sequence(new_query_string_dict)

    if bucket_name := uses_host_addressing(request.headers):
        # if the request is host addressed, we need to remove the bucket from the host and set it in the path
        path = f"/{bucket_name}{request.path}"
        host = request.host.removeprefix(f"{bucket_name}.")
    else:
        path = request.path
        host = request.host

    # we need to URL encode the path, as the key needs to be urlencoded for the signature to match
    encoded_path = urlparse.quote(path)

    reversed_url = f"{request.scheme}://{host}{encoded_path}?{new_query_string}"

    reversed_headers = HTTPHeaders()
    for key, value in new_headers.items():
        reversed_headers[key] = value

    return urlsplit(reversed_url), reversed_headers


def validate_presigned_url_s3v4(context: RequestContext) -> None:
    """
    Validate the presigned URL signed with SigV4.
    :param context: RequestContext
    :return:
    """

    sigv4_context, exception = _find_valid_signature_through_ports(context)
    add_headers_to_original_request(context, sigv4_context.headers_in_qs)

    if sigv4_context.missing_signed_headers:
        if config.S3_SKIP_SIGNATURE_VALIDATION:
            LOG.warning(
                "There were headers present in the request which were not signed (%s), "
                "but not raising an error, as S3_SKIP_SIGNATURE_VALIDATION=1",
                ", ".join(sigv4_context.missing_signed_headers),
            )
        else:
            raise AccessDenied(
                "There were headers present in the request which were not signed",
                HostId=FAKE_HOST_ID,
                HeadersNotSigned=", ".join(sigv4_context.missing_signed_headers),
            )

    if exception:
        if config.S3_SKIP_SIGNATURE_VALIDATION:
            LOG.warning(
                "Signatures do not match, but not raising an error, as S3_SKIP_SIGNATURE_VALIDATION=1"
            )
        else:
            ex: SignatureDoesNotMatch = create_signature_does_not_match_sig_v4(
                exception, sigv4_context.credentials.access_key_id
            )
            raise ex

    # Checking whether the url is expired or not
    query_parameters = context.request.args
    # TODO: should maybe try/except here -> create auth params validation before checking signature, above!!
    x_amz_date = datetime.datetime.strptime(query_parameters["X-Amz-Date"], "%Y%m%dT%H%M%SZ")
    x_amz_expires = int(query_parameters["X-Amz-Expires"])
    x_amz_expires_dt = datetime.timedelta(seconds=x_amz_expires)
    expiration_time = x_amz_date + x_amz_expires_dt
    expiration_time = expiration_time.replace(tzinfo=datetime.timezone.utc)

    if is_expired(expiration_time):
        if config.S3_SKIP_SIGNATURE_VALIDATION:
            LOG.warning(
                "Signature is expired, but not raising an error, as S3_SKIP_SIGNATURE_VALIDATION=1"
            )
        else:
            raise AccessDenied(
                "Request has expired",
                HostId=FAKE_HOST_ID,
                Expires=expiration_time.timestamp(),
                ServerTime=time.time(),
                X_Amz_Expires=x_amz_expires,
            )


def _find_valid_signature_through_ports(context: RequestContext) -> FindSigV4Result:
    """
    Tries to validate the signature of the received request. If it fails, it will iterate through known LocalStack
    ports to try to find a match (the host is used for the calculation).
    If it fails to find a valid match, it will return NotValidSigV4Signature context data
    :param context:
    :return: FindSigV4Result: contains a tuple with the signature if found, or NotValidSigV4Signature context
    """
    request_sig = context.request.args["X-Amz-Signature"]

    sigv4_context = S3SigV4SignatureContext(context=context)
    # get the port of the request
    match = re.match(HOST_COMBINATION_REGEX, sigv4_context.host)
    request_port = match.group(2) if match else None

    # get the signature from the request
    signature, canonical_request, string_to_sign = sigv4_context.get_signature_data()
    if signature == request_sig:
        return sigv4_context, None

    # if the signature does not match, save the data for the exception
    exception_context = NotValidSigV4SignatureContext(
        signature_provided=request_sig,
        string_to_sign=string_to_sign,
        canonical_request=canonical_request,
    )

    # we try to iterate through possible ports, to match the signature
    for port in PORT_REPLACEMENT:
        if request_port:
            # the request has already been tested before the loop, skip
            if request_port == port:
                continue
            sigv4_context.update_host_port(new_host_port=port, original_host_port=request_port)

        else:
            sigv4_context.update_host_port(new_host_port=port)

        # we ignore the additional data because we want the exception raised to match the original request
        signature, _, _ = sigv4_context.get_signature_data()
        if signature == request_sig:
            return sigv4_context, None

    # Return the exception data from the original request after trying to loop through ports
    return sigv4_context, exception_context


class S3SigV4SignatureContext:
    def __init__(self, context: RequestContext):
        self.request = context.request
        self._query_parameters = context.request.args
        self._headers = context.request.headers
        self._bucket, _ = extract_bucket_name_and_key_from_headers_and_path(
            context.request.headers, get_raw_path(context.request)
        )
        self._bucket = urlparse.unquote(self._bucket)
        self._request_method = context.request.method
        self.missing_signed_headers = []

        region = self._get_region_from_x_amz_credential(self._query_parameters["X-Amz-Credential"])
        credentials = get_credentials_from_parameters(self._query_parameters, region)
        signing_credentials = ReadOnlyCredentials(
            credentials.access_key_id,
            credentials.secret_access_key,
            credentials.security_token,
        )
        self.credentials = credentials
        expires = int(self._query_parameters["X-Amz-Expires"])
        self.signature_date = self._query_parameters["X-Amz-Date"]

        self.signer = S3SigV4QueryAuthValidation(signing_credentials, "s3", region, expires=expires)
        sig_headers, qs, headers_in_qs = self._get_signed_headers_and_filtered_query_string()
        self.signed_headers = sig_headers
        self.request_query_string = qs
        self.headers_in_qs = headers_in_qs | sig_headers
        self.headers_in_qs["Authorization"] = self._get_authorization_header_from_qs(
            self._query_parameters
        )

        if forwarded_from_virtual_host_addressed_request(self._headers):
            # FIXME: maybe move this so it happens earlier in the chain when using virtual host?
            if not is_bucket_name_valid(self._bucket):
                raise InvalidBucketName(BucketName=self._bucket)
            netloc = self._headers.get(S3_VIRTUAL_HOST_FORWARDED_HEADER)
            self.host = netloc
            self._original_host = netloc
            self.signed_headers["host"] = netloc
            # the request comes from the Virtual Host router, we need to remove the bucket from the path
            splitted_path = self.request.path.split("/", maxsplit=2)
            self.path = f"/{splitted_path[-1]}"

        else:
            netloc = urlparse.urlparse(self.request.url).netloc
            self.host = netloc
            self._original_host = netloc
            if (host_addressed := uses_host_addressing(self._headers)) and not is_bucket_name_valid(
                self._bucket
            ):
                raise InvalidBucketName(BucketName=self._bucket)

            if not host_addressed and not self.request.path.startswith(f"/{self._bucket}"):
                # if in path style, check that the path starts with the bucket
                # our path has been sanitized, we should use the un-sanitized one
                splitted_path = self.request.path.split("/", maxsplit=2)
                self.path = f"/{self._bucket}/{splitted_path[-1]}"
            else:
                self.path = self.request.path

        # we need to URL encode the path, as the key needs to be urlencoded for the signature to match
        self.path = urlparse.quote(self.path)
        self.aws_request = self._get_aws_request()

    def update_host_port(self, new_host_port: str, original_host_port: str = None):
        """
        Update the host port of the context with the provided one, format `:{port}`
        :param new_host_port:
        :param original_host_port:
        :return:
        """
        if original_host_port:
            updated_netloc = self._original_host.replace(original_host_port, new_host_port)
        else:
            updated_netloc = f"{self._original_host}{new_host_port}"
        self.host = updated_netloc
        self.signed_headers["host"] = updated_netloc
        self.aws_request = self._get_aws_request()

    @property
    def request_url(self) -> str:
        return f"{self.request.scheme}://{self.host}{self.path}?{self.request_query_string}"

    def get_signature_data(self) -> tuple[bytes, str, str]:
        """
        Uses the signer to return the signature and the data used to calculate it
        :return: signature, canonical_request and string_to_sign
        """
        return self.signer.add_auth(self.aws_request)

    def _get_signed_headers_and_filtered_query_string(
        self,
    ) -> tuple[dict[str, str], str, dict[str, str]]:
        """
        Transforms the original headers and query parameters to the headers and query string used to sign the
        original request.
        Allows us to recreate the original request, and also retrieve query string parameters that should be headers
        :raises AccessDenied if the request contains headers that were not in X-Amz-SignedHeaders and started with x-amz
        :return: the headers used to sign the request and the query string without X-Amz-Signature, and the query string
        parameters which should be put back in the headers
        """
        headers = copy.copy(self._headers)
        # set automatically by the handler chain, we don't want that
        headers.pop("Authorization", None)
        signed_headers = self._query_parameters.get("X-Amz-SignedHeaders")

        new_query_args = {}
        query_args_to_headers = {}
        for qs_parameter, qs_value in self._query_parameters.items():
            # skip the signature
            if qs_parameter == "X-Amz-Signature":
                continue

            qs_param_low = qs_parameter.lower()
            if (
                qs_parameter not in SIGNATURE_V4_PARAMS
                and qs_param_low.startswith("x-amz-")
                and qs_param_low not in headers
            ):
                if qs_param_low in signed_headers:
                    # AWS JS SDK does not behave like boto, and will add some parameters as query string when signing
                    # when boto would not. this difference in behaviour would lead to pre-signed URLs generated by the
                    # JS SDK to be invalid for the boto signer.
                    # This fixes the behaviour by manually adding the parameter to the headers like boto would, if the
                    # SDK put them in the SignedHeaders
                    # this is especially valid for headers starting with x-amz-server-side-encryption, treated
                    # specially in the old JS SDK v2
                    headers.add(qs_param_low, qs_value)
                else:
                    # The JS SDK is adding the `x-amz-checksum-crc32` header to query parameters, even though it cannot
                    # know in advance the actual checksum. Those are ignored by AWS, if they're not put in the
                    # SignedHeaders
                    if not qs_param_low.startswith("x-amz-checksum-"):
                        query_args_to_headers[qs_param_low] = qs_value

            new_query_args[qs_parameter] = qs_value

        signature_headers = {}
        for header, value in headers.items():
            header_low = header.lower()
            if header_low.startswith("x-amz-") and header_low not in signed_headers.lower():
                if header_low in IGNORED_SIGV4_HEADERS:
                    continue
                self.missing_signed_headers.append(header_low)
            if header_low in signed_headers:
                signature_headers[header_low] = value

        new_query_string = percent_encode_sequence(new_query_args)
        return signature_headers, new_query_string, query_args_to_headers

    def _get_aws_request(self) -> AWSRequest:
        """
        Creates and returns the AWSRequest needed for S3SigV4QueryAuth signer
        :return: AWSRequest
        """
        request_dict = {
            "method": self._request_method,
            "url": self.request_url,
            "body": b"",
            "headers": self.signed_headers,
            "context": {
                "is_presign_request": True,
                "use_global_endpoint": True,
                "signing": {"bucket": self._bucket},
                "timestamp": self.signature_date,
            },
        }
        return create_request_object(request_dict)

    @staticmethod
    def _get_region_from_x_amz_credential(credential: str) -> str:
        if not (split_creds := credential.split("/")) or len(split_creds) != 5:
            raise AuthorizationQueryParametersError(
                'Error parsing the X-Amz-Credential parameter; the Credential is mal-formed; expecting "<YOUR-AKID>/YYYYMMDD/REGION/SERVICE/aws4_request".',
                HostId=FAKE_HOST_ID,
            )

        return split_creds[2]

    @staticmethod
    def _get_authorization_header_from_qs(parameters: dict) -> str:
        # See https://docs.aws.amazon.com/AmazonS3/latest/API/sigv4-auth-using-authorization-header.html
        # Recreating the Authorization header from the query string parameters of a pre-signed request
        authorization_keys = ["X-Amz-Credential", "X-Amz-SignedHeaders", "X-Amz-Signature"]
        values = [
            f"{param.removeprefix('X-Amz-')}={parameters[param]}" for param in authorization_keys
        ]

        authorization = f"{parameters['X-Amz-Algorithm']}{','.join(values)}"
        return authorization


def add_headers_to_original_request(context: RequestContext, headers: Mapping[str, str]):
    for header, value in headers.items():
        context.request.headers.add(header, value)


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


def validate_post_policy(
    request_form: ImmutableMultiDict, additional_policy_metadata: dict
) -> None:
    """
    Validate the pre-signed POST with its policy contained
    For now, only validates its expiration
    SigV2: https://docs.aws.amazon.com/AmazonS3/latest/userguide/HTTPPOSTExamples.html
    SigV4: https://docs.aws.amazon.com/AmazonS3/latest/API/sigv4-authentication-HTTPPOST.html

    :param request_form: the form data contained in the pre-signed POST request
    :param additional_policy_metadata: additional metadata needed to validate the policy (bucket name, object size)
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

    form_dict = {k.lower(): v for k, v in request_form.items()}

    policy = form_dict.get("policy")
    if not policy:
        # A POST request needs a policy except if the bucket is publicly writable
        return

    # TODO: this does validation of fields only for now
    is_v4 = _is_match_with_signature_fields(form_dict, SIGNATURE_V4_POST_FIELDS)
    is_v2 = _is_match_with_signature_fields(form_dict, SIGNATURE_V2_POST_FIELDS)

    if not is_v2 and not is_v4:
        ex: AccessDenied = AccessDenied("Access Denied")
        ex.HostId = FAKE_HOST_ID
        raise ex

    try:
        policy_decoded = json.loads(base64.b64decode(policy).decode("utf-8"))
    except ValueError:
        # this means the policy has been tampered with
        signature = form_dict.get("signature") if is_v2 else form_dict.get("x-amz-signature")
        credentials = get_credentials_from_parameters(request_form, "us-east-1")
        ex: SignatureDoesNotMatch = create_signature_does_not_match_sig_v2(
            request_signature=signature,
            string_to_sign=policy,
            access_key_id=credentials.access_key_id,
        )
        raise ex

    if expiration := policy_decoded.get("expiration"):
        if is_expired(_parse_policy_expiration_date(expiration)):
            ex: AccessDenied = AccessDenied("Invalid according to Policy: Policy expired.")
            ex.HostId = FAKE_HOST_ID
            raise ex

    # TODO: validate the signature

    # See https://docs.aws.amazon.com/AmazonS3/latest/API/sigv4-HTTPPOSTConstructPolicy.html
    # for the list of conditions and what matching they support
    # TODO:
    #  1. only support the kind of matching the field supports: `success_action_status` does not support `starts-with`
    #  matching
    #  2. if there are fields that are not defined in the policy, we should reject it

    # Special case for LEGACY_V2: do not validate the conditions. Remove this check once we remove legacy_v2
    if not additional_policy_metadata:
        return

    conditions = policy_decoded.get("conditions", [])
    for condition in conditions:
        if not _verify_condition(condition, form_dict, additional_policy_metadata):
            str_condition = str(condition).replace("'", '"')
            raise AccessDenied(
                f"Invalid according to Policy: Policy Condition failed: {str_condition}",
                HostId=FAKE_HOST_ID,
            )


def _verify_condition(condition: list | dict, form: dict, additional_policy_metadata: dict) -> bool:
    if isinstance(condition, dict) and len(condition) > 1:
        raise CommonServiceException(
            code="InvalidPolicyDocument",
            message="Invalid Policy: Invalid Simple-Condition: Simple-Conditions must have exactly one property specified.",
        )

    match condition:
        case {**kwargs}:
            # this is the most performant to check for a dict with only one key
            # alternative version is `key, val = next(iter(dict))`
            for key, val in kwargs.items():
                k = key.lower()
                if k == "bucket":
                    return additional_policy_metadata.get("bucket") == val
                else:
                    return form.get(k) == val

        case ["eq", key, value]:
            k = key.lower()
            if k == "$bucket":
                return additional_policy_metadata.get("bucket") == value

            return k.startswith("$") and form.get(k.lstrip("$")) == value

        case ["starts-with", key, value]:
            # You can set the `starts-with` value to an empty string to accept anything
            return key.startswith("$") and (
                not value or form.get(key.lstrip("$").lower(), "").startswith(value)
            )

        case ["content-length-range", start, end]:
            size = additional_policy_metadata.get("content_length", 0)
            try:
                start, end = int(start), int(end)
            except ValueError:
                return False

            if size < start:
                raise EntityTooSmall(
                    "Your proposed upload is smaller than the minimum allowed size",
                    ProposedSize=size,
                    MinSizeAllowed=start,
                )
            elif size > end:
                raise EntityTooLarge(
                    "Your proposed upload exceeds the maximum allowed size",
                    ProposedSize=size,
                    MaxSizeAllowed=end,
                    HostId=FAKE_HOST_ID,
                )
            else:
                return True


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
    request_form: dict[str, str], signature_fields: list[str]
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
                argument_name = (
                    capitalize_header_name_from_snake_case(p) if "-" in p else p.capitalize()
                )
                # AWSAccessKeyId is a special case
                if argument_name == "Awsaccesskeyid":
                    argument_name = "AWSAccessKeyId"

                ex: InvalidArgument = _create_invalid_argument_exc(
                    message=f"Bucket POST must contain a field named '{argument_name}'.  If it is specified, please check the order of the fields.",
                    name=argument_name,
                    value="",
                    host_id=FAKE_HOST_ID,
                )
                raise ex

        return True
    return False
