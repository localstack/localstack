from moto.iam import iam_backends
from moto.iam.models import IAMBackend

from localstack.aws.api import RequestContext
from localstack.aws.api.iam import SimulatePolicyResponse, SimulatePrincipalPolicyRequest
from localstack.services.iam.resources.iam_policy_simulator import IAMPolicySimulator
from localstack.utils import json


class BasicIAMPolicySimulator(IAMPolicySimulator):
    def simulate_principal_policy(
        self, request: SimulatePrincipalPolicyRequest, context: RequestContext
    ) -> SimulatePolicyResponse:
        backend = self.get_iam_backend(context)
        policies = self.get_policies_from_principal(backend, request.get("PolicySourceArn"))

        def _get_statements_from_policy_list(_policies: list[str]):
            statements = []
            for policy_str in _policies:
                policy_dict = json.loads(policy_str)
                if isinstance(policy_dict["Statement"], list):
                    statements.extend(policy_dict["Statement"])
                else:
                    statements.append(policy_dict["Statement"])
            return statements

        policy_statements = _get_statements_from_policy_list(policies)

        evaluations = [
            self.build_evaluation_result(action_name, resource_arn, policy_statements)
            for action_name in request.get("ActionNames")
            for resource_arn in request.get("ResourceArns")
        ]

        response = SimulatePolicyResponse()
        response["IsTruncated"] = False
        response["EvaluationResults"] = evaluations

        return response

    @staticmethod
    def get_iam_backend(context: RequestContext) -> IAMBackend:
        return iam_backends[context.account_id][context.partition]

    @staticmethod
    def get_policies_from_principal(backend: IAMBackend, principal_arn: str) -> list[dict]:
        policies = []
        if ":role" in principal_arn:
            role_name = principal_arn.split("/")[-1]

            policies.append(backend.get_role(role_name=role_name).assume_role_policy_document)

            policy_names = backend.list_role_policies(role_name=role_name)
            policies.extend(
                [
                    backend.get_role_policy(role_name=role_name, policy_name=policy_name)[1]
                    for policy_name in policy_names
                ]
            )

            attached_policies, _ = backend.list_attached_role_policies(role_name=role_name)
            policies.extend([policy.document for policy in attached_policies])

        if ":group" in principal_arn:
            print(principal_arn)
            group_name = principal_arn.split("/")[-1]
            policy_names = backend.list_group_policies(group_name=group_name)
            policies.extend(
                [
                    backend.get_group_policy(group_name=group_name, policy_name=policy_name)[1]
                    for policy_name in policy_names
                ]
            )

            attached_policies, _ = backend.list_attached_group_policies(group_name=group_name)
            policies.extend([policy.document for policy in attached_policies])

        if ":user" in principal_arn:
            print(principal_arn)
            user_name = principal_arn.split("/")[-1]
            policy_names = backend.list_user_policies(user_name=user_name)
            policies.extend(
                [
                    backend.get_user_policy(user_name=user_name, policy_name=policy_name)[1]
                    for policy_name in policy_names
                ]
            )

            attached_policies, _ = backend.list_attached_user_policies(user_name=user_name)
            policies.extend([policy.document for policy in attached_policies])

        return policies
