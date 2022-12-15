import dataclasses
import json
import logging
import re
from datetime import datetime, timedelta, timezone
from typing import Tuple

from botocore.auth import SigV4Auth
from botocore.awsrequest import AWSRequest, create_request_object
from botocore.compat import HTTPHeaders
from botocore.credentials import ReadOnlyCredentials

from localstack import config
from localstack.aws.api import CommonServiceException, RequestContext
from localstack.aws.chain import Handler, HandlerChain
from localstack.constants import DEFAULT_AWS_ACCOUNT_ID
from localstack.http import Request, Response
from localstack.http.request import restore_payload
from localstack.runtime import hooks
from localstack.utils.aws.aws_stack import is_internal_call_context
from localstack.utils.strings import to_str

LOG = logging.getLogger(__name__)

X_AMZ_DATE_FORMAT = "%Y%m%dT%H%M%SZ"

ROOT_ACCESS_KEYS = {}


@dataclasses.dataclass
class AuthorizationData:
    signature_alg: str
    access_key_id: str
    region: str
    service: str
    signed_headers: list[str]
    signature: str


class InvalidSignatureException(CommonServiceException):
    def __init__(self, message: str):
        super().__init__(message=message, code="InvalidSignatureException", status_code=403)


class UnrecognizedClientException(CommonServiceException):
    def __init__(self, message: str):
        super().__init__(message=message, code="UnrecognizedClientException", status_code=403)


class SignatureHandler(Handler):
    """
    Handler which enforces request signatures
    This handler needs to be at the top of the handler chain to ensure that the signatures are enforced before any
    commands are executed, if activated.
    """

    def __init__(self):
        self.signature_validator = SignatureValidator()

    def __call__(self, chain: HandlerChain, context: RequestContext, response: Response) -> None:
        if not config.SIGNATURE_VERIFICATION or is_internal_call_context(context.request.headers):
            return
        self.signature_validator.verify_signature(context.request)


def create_root_key_for_account(account: str) -> Tuple[str, str]:
    from moto.iam.utils import generate_access_key_id_from_account_id, random_alphanumeric

    access_key_id = generate_access_key_id_from_account_id(account_id=account, prefix="LKIA")
    secret_access_key = random_alphanumeric(40)
    ROOT_ACCESS_KEYS[access_key_id] = FakeAccessKey(secret_access_key)
    return access_key_id, secret_access_key


class SignatureResource:
    """
    Resource to list information about plux plugins.
    """

    def __init__(self):
        print("Inited!")

    def on_post(self, request):
        data = request.get_json(True, True)
        if not data:
            return Response("invalid request", 400)
        account = data.get("account")
        password = data.get("password")
        if not account or not password:
            return Response("You have to include username and password", 400)
        if password != "test123":
            return Response("Wrong password", 400)

        access_key_id, secret_access_key = create_root_key_for_account(account)
        return Response(
            json.dumps({"access_key_id": access_key_id, "secret_access_key": secret_access_key}),
            201,
        )


class SignatureValidator:
    def verify_signature(self, request: Request):
        # TODO add query as well
        if "Authorization" not in request.headers:
            raise InvalidSignatureException("No authorization header!")  # TODO correct exception
        authorization_data = self.parse_authorization_header(request.headers["Authorization"])
        # TODO validate list (x-amz necessity for example)
        aws_request = self.create_aws_request(
            request=request, authorization_data=authorization_data
        )
        # time should be x-amz-date if present, otherwise date (has to be iso8601 - basic format then)
        # see https://docs.aws.amazon.com/STS/latest/APIReference/CommonParameters.html#CommonParameters-X-Amz-Date
        aws_request.context["timestamp"] = request.headers.get("x-amz-date") or request.headers.get(
            "date"
        )
        self.check_expired(aws_request.context["timestamp"])
        secret_key = self.get_secret_key_for_access_key_id(authorization_data.access_key_id)
        if not secret_key:
            raise UnrecognizedClientException(
                message="The security token included in the request is invalid."
            )
        credentials = ReadOnlyCredentials(
            access_key=authorization_data.access_key_id, secret_key=secret_key, token=""
        )
        auth_validator = SigV4AuthValidator(
            credentials=credentials,
            region_name=authorization_data.region,
            service_name=authorization_data.service,
        )
        signature = auth_validator.add_auth(aws_request)
        if signature != authorization_data.signature:
            LOG.debug("Calculated signature: %s", signature)
            LOG.debug("Sent signature: %s", authorization_data.signature)
            raise InvalidSignatureException(
                message="The request signature we calculated does not match the signature you provided. Check your AWS Secret Access Key and signing method. Consult the service documentation for details."
            )

    def create_aws_request(
        self, request: Request, authorization_data: AuthorizationData
    ) -> AWSRequest:
        """
        Creating an AWSRequest object from the given request, to be signed by the AWSV4Signer
        :param request: Werkzeug request object
        :param authorization_data:
        :return:
        """
        signed_headers = HTTPHeaders()
        for key, value in [
            header
            for header in request.headers
            if header[0].lower() in authorization_data.signed_headers
        ]:
            signed_headers.add_header(key, value)
        if set(authorization_data.signed_headers) - set(request.headers.keys(lower=True)):
            raise InvalidSignatureException("A header is missing m'lord")
        if "host" not in signed_headers:
            raise InvalidSignatureException("A naughty host header is not signed m'lord")

        for k, v in request.headers:
            if k.lower().startswith("x-amz-") and k not in signed_headers:
                raise InvalidSignatureException("A naughty header is not signed m'lord")

        request_dict = {
            "method": request.method,
            "url": request.url,
            "body": restore_payload(request),
            "headers": signed_headers,
            "context": {
                "use_global_endpoint": True,
            },
        }
        return create_request_object(request_dict)

    @classmethod
    def check_expired(cls, timestamp: str):
        x_amz_date = datetime.strptime(timestamp, X_AMZ_DATE_FORMAT).replace(tzinfo=timezone.utc)
        now = datetime.now(tz=timezone.utc)
        current_minus_expiration = now - timedelta(minutes=5)

        is_expired = current_minus_expiration > x_amz_date
        if is_expired:
            raise UnrecognizedClientException(
                f"Signature expired: {timestamp} is now earlier than {current_minus_expiration.strftime(X_AMZ_DATE_FORMAT)} ({now.strftime(X_AMZ_DATE_FORMAT)} - 5 min.)"
            )

    @classmethod
    def parse_authorization_header(cls, authorization_header: str) -> AuthorizationData:
        """
        Parse the authorization header

        :param authorization_header: Authorization header
        :return: Parsed authorization data
        """
        if authorization_header.startswith("AWS4"):
            # sigv4
            signature_algorithm = re.search(r"AWS4-[^\s]*", authorization_header).lastgroup
            credential_match = re.search(
                r"Credential=(?P<key>[^/]+)/[^/]*/(?P<region>[^/]*)/(?P<service>[^/]*)/",
                authorization_header,
            )
            access_key_id = credential_match.group("key")
            region = credential_match.group("region")
            service = credential_match.group("service")
            signed_headers = [
                header.lower()
                for header in re.search(r"SignedHeaders=([^,]+)", authorization_header)
                .group(1)
                .split(";")
            ]
            signature = re.search(r"Signature=([^,]+)", authorization_header).group(1)
        elif authorization_header.startswith("AWS"):
            # sigv2
            signature_algorithm = "AWS"
            auth_partition = authorization_header.partition(" ")
            sig_partition = auth_partition[2].partition(":")
            access_key_id = sig_partition[0]
            signature = sig_partition[2]
            region = ""
            service = ""
            signed_headers = []
        else:
            # what's this
            raise InvalidSignatureException(
                "No valid authorization header '%s'", authorization_header
            )
        return AuthorizationData(
            signature_alg=signature_algorithm,
            access_key_id=access_key_id,
            signed_headers=signed_headers,
            signature=signature,
            region=region,
            service=service,
        )

    @classmethod
    def get_secret_key_for_access_key_id(cls, access_key_id: str) -> str | None:
        """
        Get secret access key from (valid) access key id

        :param access_key_id: Access key id to retrieve secret access key for
        :return: Secret access key
        """
        from moto.iam.models import iam_backends

        access_keys = {}
        for iam_account_backend in iam_backends.values():
            access_keys |= iam_account_backend["global"].access_keys
        access_keys |= ROOT_ACCESS_KEYS
        try:
            return access_keys[access_key_id].secret_access_key
        except KeyError:
            if not config.SIGNATURE_STRICT_MODE:
                if access_key_id == "test":
                    return "test"
            return None


class SigV4AuthValidator(SigV4Auth):
    def add_auth(self, request) -> str:
        from botocore.exceptions import NoCredentialsError

        if self.credentials is None:
            raise NoCredentialsError()
        # This could be a retry.  Make sure the previous
        # authorization header is removed first.
        self._modify_request_before_signing(request)
        canonical_request = self.canonical_request(request)
        # LOG.debug("Calculating signature using v4 auth.")
        # LOG.debug("CanonicalRequest:\n%s", canonical_request)
        string_to_sign = self.string_to_sign(request, canonical_request)
        # LOG.debug("StringToSign:\n%s", string_to_sign)
        signature = self.signature(string_to_sign, request)
        # LOG.debug("Signature:\n%s", signature)
        return to_str(signature)


@dataclasses.dataclass
class FakeAccessKey:
    secret_access_key: str


@hooks.on_infra_ready(priority=10)
def create_root_credentials():

    accounts = [DEFAULT_AWS_ACCOUNT_ID]
    for account in accounts:
        access_key_id, secret_access_key = create_root_key_for_account(account)
        LOG.info("===================================================")
        LOG.info("")
        LOG.info("ACCOUNT: %s", account)
        LOG.info("AWS_ACCESS_KEY_ID=%s", access_key_id)
        LOG.info("AWS_SECRET_ACCESS_KEY=%s", secret_access_key)
        LOG.info("")
    LOG.info("===================================================")
