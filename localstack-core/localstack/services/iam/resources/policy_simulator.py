import abc
import json
from typing import TYPE_CHECKING
from urllib.parse import unquote

from localstack.aws.api import RequestContext
from localstack.aws.api.iam import (
    ActionNameType,
    EvaluationResult,
    PolicyEvaluationDecisionType,
    ResourceNameType,
    SimulatePolicyResponse,
    SimulatePrincipalPolicyRequest,
)
from localstack.services.iam.models import IamStore

if TYPE_CHECKING:
    from localstack.services.iam.provider import IamProvider


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
    def __init__(self, provider: "IamProvider"):
        self.provider = provider

    def simulate_principal_policy(
        self,
        context: RequestContext,
        request: SimulatePrincipalPolicyRequest,
    ) -> SimulatePolicyResponse:
        store = self.provider._get_store(context)
        policies = self.get_policies_from_principal(store, request.get("PolicySourceArn"))

        def _get_statements_from_policy_list(_policies: list[str]):
            statements = []
            for policy_str in _policies:
                policy_dict = json.loads(unquote(policy_str))
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

    def _get_policy_document(self, store: IamStore, policy_arn: str) -> str:
        if self.provider._is_managed_policy(policy_arn):
            policy = self.provider._aws_managed_policy_cache[policy_arn]
        else:
            policy = store.MANAGED_POLICIES[policy_arn]
        default_version = policy.policy["DefaultVersionId"]
        return policy.versions[default_version]["Document"]

    def get_policies_from_principal(self, store: IamStore, principal_arn: str) -> list[str]:
        policies: list[str] = []
        entity = None
        if ":role" in principal_arn:
            role_name = principal_arn.split("/")[-1]
            entity = self.provider._get_role_entity(store, role_name)

            policies.append(entity.role["AssumeRolePolicyDocument"])

        if ":group" in principal_arn:
            group_name = principal_arn.split("/")[-1]
            entity = self.provider._get_group_entity(store, group_name)

        if ":user" in principal_arn:
            user_name = principal_arn.split("/")[-1]
            entity = self.provider._get_user_entity(store, user_name)

        if entity:
            policies.extend(entity.inline_policies.values())

            attached_policies = entity.attached_policy_arns
            policies.extend(
                [self._get_policy_document(store, policy_arn) for policy_arn in attached_policies]
            )

        return policies
