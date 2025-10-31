import abc

from localstack.aws.api import RequestContext
from localstack.aws.api.iam import SimulatePrincipalPolicyRequest


class IAMPolicySimulator(abc.ABC):
    @abc.abstractmethod
    def simulate_principal_policy(
        self, context: RequestContext, request: SimulatePrincipalPolicyRequest
    ):
        """
        Simulate principal policy
        :param request: SimulatePrincipalPolicyRequest
        :param context: RequestContext
        :return: SimulatePrincipalResponse
        """
        pass
