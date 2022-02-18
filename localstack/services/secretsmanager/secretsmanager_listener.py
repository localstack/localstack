import json
import logging

from requests.models import Request

from localstack.aws.proxy import (
    AsfWithFallbackListener,
    AsfWithPersistingFallbackListener,
    AwsApiListener,
)
from localstack.services.moto import MotoFallbackDispatcher
from localstack.services.secretsmanager.provider import SecretsmanagerProvider
from localstack.utils.aws import aws_stack
from localstack.utils.aws.aws_responses import MessageConversion
from localstack.utils.common import to_str
from localstack.utils.persistence import PersistingProxyListener

LOG = logging.getLogger(__name__)


def secretsmanager_transform_request_data(data: bytes) -> dict:
    data_dict = json.loads(to_str(data or "{}"))
    secret_id = data_dict.get("SecretId") or ""
    if ":" in secret_id:
        parts = secret_id.split(":")
        if parts[3] != aws_stack.get_region():
            LOG.info(
                'Unexpected request region %s for secret "%s"',
                aws_stack.get_region(),
                secret_id,
            )
        # secret ARN ends with "-<randomId>" which we remove in the request for upstream compatibility
        # if the full arn is being sent then we remove the string in the end
        if parts[-1][-7] == "-":
            data_dict["SecretId"] = parts[-1][: len(parts[-1]) - 7]
        elif parts[-1][-1] != "-":
            data_dict["SecretId"] = data_dict["SecretId"] + "-"
    return data_dict


class ProxyListenerSecretsManager(PersistingProxyListener):
    def api_name(self):
        return "secretsmanager"

    def forward_request(self, method, path, data, headers):
        data_dict = secretsmanager_transform_request_data(data)
        data_str = json.dumps(data_dict)
        return Request(data=data_str, headers=headers, method=method)

    def return_response(self, method, path, data, headers, response):
        super(ProxyListenerSecretsManager, self).return_response(
            method, path, data, headers, response
        )
        if response.content:
            return MessageConversion.fix_account_id(response)


class AwsApiListenerSecretsManager(AwsApiListener):
    def __init__(self):
        super().__init__("secretsmanager", SecretsmanagerProvider())

    @staticmethod
    def __transform_request_data(data: bytes) -> bytes:
        data_dict = secretsmanager_transform_request_data(data)
        return bytes(json.dumps(data_dict), "utf-8")

    def forward_request(self, method, path, data, headers):
        return super(AwsApiListenerSecretsManager, self).forward_request(
            method, path, self.__transform_request_data(data), headers
        )

    def return_response(self, method, path, data, headers, response):
        super(AwsApiListenerSecretsManager, self).return_response(
            method, path, data, headers, response
        )
        if response.content:
            return MessageConversion.fix_account_id(response)


class AsfWithFallbackListenerSecretsManager(AsfWithFallbackListener):
    def __init__(self):
        super().__init__(
            "secretsmanager",
            MotoFallbackDispatcher(AwsApiListenerSecretsManager()),
            ProxyListenerSecretsManager(),
        )


class AsfWithPersistingFallbackListenerSecretsManager(AsfWithPersistingFallbackListener):
    def __init__(self):
        super().__init__(
            "secretsmanager", AsfWithFallbackListenerSecretsManager(), ProxyListenerSecretsManager()
        )
