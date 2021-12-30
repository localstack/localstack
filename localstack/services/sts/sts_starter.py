from moto.sts.responses import TokenResponse

from localstack import config
from localstack.services.infra import start_moto_server


def apply_patches():
    def get_caller_identity(self, *args, **kwargs):
        result = get_caller_identity_orig(self, *args, **kwargs)
        username = config.TEST_IAM_USER_NAME or "localstack"
        result = result.replace("user/moto", f"user/{username}")
        return result

    get_caller_identity_orig = TokenResponse.get_caller_identity
    TokenResponse.get_caller_identity = get_caller_identity


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
