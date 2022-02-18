import json
import logging

from localstack.aws.proxy import AwsApiListener
from localstack.services.secretsmanager.provider import SecretsmanagerProvider
from localstack.utils.aws import aws_stack
from localstack.utils.aws.aws_responses import MessageConversion
from localstack.utils.common import to_str

LOG = logging.getLogger(__name__)


class AWSSecretsManagerListener(AwsApiListener):
    def __init__(self):
        self.provider = SecretsmanagerProvider()
        super().__init__("secretsmanager", self.provider)

    @staticmethod
    def __transform_request_data(data: bytes) -> bytes:
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

        return bytes(json.dumps(data_dict), "utf-8")

    def forward_request(self, method, path, data, headers):
        return super(AWSSecretsManagerListener, self).forward_request(
            method, path, self.__transform_request_data(data), headers
        )

    def return_response(self, method, path, data, headers, response):
        super(AWSSecretsManagerListener, self).return_response(
            method, path, data, headers, response
        )
        if response.content:
            return MessageConversion.fix_account_id(response)
