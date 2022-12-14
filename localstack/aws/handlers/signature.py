from localstack.aws.api import RequestContext
from localstack.aws.chain import Handler, HandlerChain
from localstack.http import Response


def get_secret_key_for_access_key_id(access_key_id: str) -> str | None:
    from moto.iam.models import iam_backends

    access_keys = {}
    for iam_account_backend in iam_backends.values():
        access_keys |= iam_account_backend["global"].access_keys
    try:
        return access_keys[access_key_id].secret_access_key
    except KeyError:
        return None


class SignatureHandler(Handler):
    """
    Handler which enforces request signatures
    This handler needs to be at the top of the handler chain to ensure that the signatures are enforced before any
    commands are executed, if activated.
    """

    def __call__(self, chain: HandlerChain, context: RequestContext, response: Response) -> None:

        pass
