from moto.iam.responses import IamResponse, GENERIC_EMPTY_TEMPLATE
from moto.iam.models import iam_backend as moto_iam_backend
from localstack import config
from localstack.constants import DEFAULT_PORT_IAM_BACKEND
from localstack.services.infra import start_moto_server


def patch_moto():
    def delete_policy(self):
        policy_arn = self._get_param('PolicyArn')
        moto_iam_backend.managed_policies.pop(policy_arn, None)
        template = self.response_template(GENERIC_EMPTY_TEMPLATE)
        return template.render(name='DeletePolicyResponse')

    if not hasattr(IamResponse, 'delete_policy'):
        IamResponse.delete_policy = delete_policy


def start_iam(port=None, asynchronous=False, update_listener=None):
    port = port or config.PORT_IAM
    patch_moto()
    return start_moto_server('iam', port, name='IAM', asynchronous=asynchronous,
        backend_port=DEFAULT_PORT_IAM_BACKEND, update_listener=update_listener)
