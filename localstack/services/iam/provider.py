from localstack.aws.api import RequestContext
from localstack.aws.api.iam import (
    ActionNameListType,
    ContextEntryListType,
    IamApi,
    ResourceHandlingOptionType,
    ResourceNameListType,
    ResourceNameType,
    SimulatePolicyResponse,
    SimulationPolicyListType,
    arnType,
    markerType,
    maxItemsType,
    policyDocumentType,
)
from localstack.services.apigateway.apigateway_starter import apply_patches
from localstack.services.moto import call_moto


class IamProvider(IamApi):
    def __init__(self):
        apply_patches()

    def simulate_principal_policy(
        self,
        context: RequestContext,
        policy_source_arn: arnType,
        action_names: ActionNameListType,
        policy_input_list: SimulationPolicyListType = None,
        permissions_boundary_policy_input_list: SimulationPolicyListType = None,
        resource_arns: ResourceNameListType = None,
        resource_policy: policyDocumentType = None,
        resource_owner: ResourceNameType = None,
        caller_arn: ResourceNameType = None,
        context_entries: ContextEntryListType = None,
        resource_handling_option: ResourceHandlingOptionType = None,
        max_items: maxItemsType = None,
        marker: markerType = None,
    ) -> SimulatePolicyResponse:
        # TODO: migrate patches from iam_starter
        res = call_moto(context)
        return res
