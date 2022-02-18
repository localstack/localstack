import json
import logging
from urllib.parse import urlsplit

from localstack.aws.api import HttpRequest
from localstack.utils.aws import aws_stack
from localstack.utils.common import to_str

from localstack.aws.proxy import AwsApiListener
from localstack.services.secretsmanager.provider import SecretsmanagerProvider


LOG = logging.getLogger(__name__)


class AWSSecretsManagerListener(AwsApiListener):

    def __init__(self):
        self.provider = SecretsmanagerProvider()
        super().__init__("secretsmanager", self.provider)

    @staticmethod
    def __transform_request_data(data: bytes) -> bytes:
        data_dict = json.loads(to_str(data or "{}"))
        secret_id = data_dict.get("SecretId", "")
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
                secret_id["SecretId"] = parts[-1][: len(parts[-1]) - 7]
            elif parts[-1][-1] != "-":
                secret_id["SecretId"] = secret_id["SecretId"] + "-"

        return bytes(json.dumps(data_dict), 'utf-8')

    def forward_request(self, method, path, data, headers):
        return super().forward_request(method, path, self.__transform_request_data(data), headers)
