from localstack.aws.api import RequestContext
from localstack.aws.chain import Handler, HandlerChain
from localstack.http import Response


def get_secret_key_for_access_key_id(access_key_id: str) -> str:
    return ""


class SignatureHandler(Handler):
    """
    Handler which enforces request signatures
    This handler needs to be at the top of the handler chain to ensure that the signatures are enforced before any
    commands are executed, if activated.
    """

    def __call__(self, chain: HandlerChain, context: RequestContext, response: Response) -> None:
        pass
