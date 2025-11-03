import abc
import json

from moto.iam import iam_backends
from moto.iam.models import IAMBackend

from localstack.aws.api import RequestContext
from localstack.aws.api.iam import (
    ActionNameType,
    EvaluationResult,
    PolicyEvaluationDecisionType,
    ResourceNameType,
    SimulatePolicyResponse,
    SimulatePrincipalPolicyRequest,
)


class IAMPolicySimulator(abc.ABC):
    @abc.abstractmethod
    def simulate_principal_policy(
        self, context: RequestContext, request: SimulatePrincipalPolicyRequest
    ) -> SimulatePolicyResponse:
        """
        Simulate principal policy
        :param request: SimulatePrincipalPolicyRequest
        :param context: RequestContext
        :return: SimulatePrincipalResponse
        """
        pass


class BasicIAMPolicySimulator(IAMPolicySimulator):
    def simulate_principal_policy(
        self,
        context: RequestContext,
        request: SimulatePrincipalPolicyRequest,
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
    def build_evaluation_result(
        action_name: ActionNameType, resource_name: ResourceNameType, policy_statements: list[dict]
    ) -> EvaluationResult:
        eval_res = EvaluationResult()
        eval_res["EvalActionName"] = action_name
        eval_res["EvalResourceName"] = resource_name
        eval_res["EvalDecision"] = PolicyEvaluationDecisionType.explicitDeny
        for statement in policy_statements:
            # TODO Implement evaluation logic here
            if (
                action_name in statement["Action"]
                and resource_name in statement["Resource"]
                and statement["Effect"] == "Allow"
            ):
                eval_res["EvalDecision"] = PolicyEvaluationDecisionType.allowed
                eval_res["MatchedStatements"] = []  # TODO: add support for statement compilation.
        return eval_res

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
