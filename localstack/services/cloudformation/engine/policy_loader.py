import logging

from samtranslator.translator.managed_policy_translator import ManagedPolicyLoader

from localstack.utils.aws import aws_stack

LOG = logging.getLogger(__name__)


policy_loader = None


def create_policy_loader() -> ManagedPolicyLoader:
    global policy_loader
    if not policy_loader:
        iam_client = aws_stack.connect_to_service("iam")
        policy_loader = ManagedPolicyLoader(iam_client=iam_client)
    return policy_loader
