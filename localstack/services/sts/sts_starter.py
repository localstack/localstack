import re

from moto.sts.responses import TokenResponse

from localstack import config
from localstack.services.infra import start_moto_server
from localstack.utils.patch import patch


def apply_patches():
    @patch(TokenResponse.get_caller_identity)
    def get_caller_identity(fn, self, *args, **kwargs):
        result = fn(self, *args, **kwargs)
        username = config.TEST_IAM_USER_NAME or "localstack"
        result = result.replace("user/moto", f"user/{username}")
        if config.TEST_IAM_USER_ID:
            search = r"(<UserId>)[^<]+(</UserId>)"
            replace = rf"\g<1>{config.TEST_IAM_USER_ID}\2"
            result = re.sub(search, replace, result, flags=re.MULTILINE)
        return result


def start_sts(port=None, asynchronous=False, update_listener=None):
    apply_patches()

    port = port or config.PORT_STS
    return start_moto_server(
        "sts",
        port,
        name="STS",
        asynchronous=asynchronous,
        update_listener=update_listener,
    )
