import copy
import json
import logging
import time
from abc import ABC
from typing import Dict, Optional

from localstack.aws.api import CommonServiceException, RequestContext
from localstack.aws.api.ssm import (
    AlarmConfiguration,
    BaselineDescription,
    BaselineId,
    BaselineName,
    Boolean,
    ClientToken,
    CreateMaintenanceWindowResult,
    CreatePatchBaselineResult,
    DeleteMaintenanceWindowResult,
    DeleteParameterResult,
    DeletePatchBaselineResult,
    DeregisterTargetFromMaintenanceWindowResult,
    DeregisterTaskFromMaintenanceWindowResult,
    DescribeMaintenanceWindowsResult,
    DescribeMaintenanceWindowTargetsResult,
    DescribeMaintenanceWindowTasksResult,
    DescribePatchBaselinesResult,
    GetParameterResult,
    GetParametersResult,
    LabelParameterVersionResult,
    LoggingInfo,
    MaintenanceWindowAllowUnassociatedTargets,
    MaintenanceWindowCutoff,
    MaintenanceWindowDescription,
    MaintenanceWindowDurationHours,
    MaintenanceWindowFilterList,
    MaintenanceWindowId,
    MaintenanceWindowMaxResults,
    MaintenanceWindowName,
    MaintenanceWindowOffset,
    MaintenanceWindowResourceType,
    MaintenanceWindowSchedule,
    MaintenanceWindowStringDateTime,
    MaintenanceWindowTargetId,
    MaintenanceWindowTaskArn,
    MaintenanceWindowTaskCutoffBehavior,
    MaintenanceWindowTaskId,
    MaintenanceWindowTaskInvocationParameters,
    MaintenanceWindowTaskParameters,
    MaintenanceWindowTaskPriority,
    MaintenanceWindowTaskType,
    MaintenanceWindowTimezone,
    MaxConcurrency,
    MaxErrors,
    NextToken,
    OperatingSystem,
    OwnerInformation,
    ParameterLabelList,
    ParameterName,
    ParameterNameList,
    PatchAction,
    PatchBaselineMaxResults,
    PatchComplianceLevel,
    PatchComplianceStatus,
    PatchFilterGroup,
    PatchIdList,
    PatchOrchestratorFilterList,
    PatchRuleGroup,
    PatchSourceList,
    PSParameterName,
    PSParameterVersion,
    PutParameterRequest,
    PutParameterResult,
    RegisterTargetWithMaintenanceWindowResult,
    RegisterTaskWithMaintenanceWindowResult,
    ServiceRole,
    SsmApi,
    TagList,
    Targets,
)
from localstack.aws.connect import connect_to
from localstack.services.moto import call_moto, call_moto_with_request
from localstack.utils.aws.arns import extract_resource_from_arn, is_arn
from localstack.utils.bootstrap import is_api_enabled
from localstack.utils.collections import remove_attributes
from localstack.utils.objects import keys_to_lower

LOG = logging.getLogger(__name__)

PARAM_PREFIX_SECRETSMANAGER = "/aws/reference/secretsmanager"


class ValidationException(CommonServiceException):
    def __init__(self, message=None):
        super().__init__("ValidationException", message=message, sender_fault=True)


class InvalidParameterNameException(ValidationException):
    def __init__(self):
        msg = (
            'Parameter name: can\'t be prefixed with "ssm" (case-insensitive). '
            "If formed as a path, it can consist of sub-paths divided by slash symbol; "
            "each sub-path can be formed as a mix of letters, numbers and the following 3 symbols .-_"
        )
        super().__init__(msg)


# TODO: check if _normalize_name(..) calls are still required here
class SsmProvider(SsmApi, ABC):
    def get_parameters(
        self,
        context: RequestContext,
        names: ParameterNameList,
        with_decryption: Boolean = None,
        **kwargs,
    ) -> GetParametersResult:
        if SsmProvider._has_secrets(names):
            return SsmProvider._get_params_and_secrets(context.account_id, context.region, names)

        norm_names = [SsmProvider._normalize_name(name, validate=True) for name in names]
        request = {"Names": norm_names, "WithDecryption": bool(with_decryption)}
        res = call_moto_with_request(context, request)

        if not res.get("InvalidParameters"):
            # note: simplifying assumption for now - only de-normalizing names if no invalid params were given
            for i in range(len(res["Parameters"])):
                self._denormalize_param_name_in_response(res["Parameters"][i], names[i])

        return GetParametersResult(**res)

    def put_parameter(
        self, context: RequestContext, request: PutParameterRequest, **kwargs
    ) -> PutParameterResult:
        name = request["Name"]
        nname = SsmProvider._normalize_name(name)
        if name != nname:
            request.update({"Name": nname})
            moto_res = call_moto_with_request(context, request)
        else:
            moto_res = call_moto(context)
        SsmProvider._notify_event_subscribers(context.account_id, context.region, nname, "Create")
        return PutParameterResult(**moto_res)

    def get_parameter(
        self,
        context: RequestContext,
        name: PSParameterName,
        with_decryption: Boolean = None,
        **kwargs,
    ) -> GetParameterResult:
        result = None

        norm_name = self._normalize_name(name, validate=True)
        details = norm_name.split("/")
        if len(details) > 4:
            service = details[3]
            if service == "secretsmanager":
                resource_name = "/".join(details[4:])
                result = SsmProvider._get_secrets_information(
                    context.account_id, context.region, norm_name, resource_name
                )

        if not result:
            result = call_moto_with_request(
                context, {"Name": norm_name, "WithDecryption": bool(with_decryption)}
            )

        self._denormalize_param_name_in_response(result["Parameter"], name)

        return GetParameterResult(**result)

    def delete_parameter(
        self, context: RequestContext, name: PSParameterName, **kwargs
    ) -> DeleteParameterResult:
        SsmProvider._notify_event_subscribers(context.account_id, context.region, name, "Delete")
        call_moto(context)  # Return type is an emtpy type.
        return DeleteParameterResult()

    def label_parameter_version(
        self,
        context: RequestContext,
        name: PSParameterName,
        labels: ParameterLabelList,
        parameter_version: PSParameterVersion = None,
        **kwargs,
    ) -> LabelParameterVersionResult:
        SsmProvider._notify_event_subscribers(
            context.account_id, context.region, name, "LabelParameterVersion"
        )
        return LabelParameterVersionResult(**call_moto(context))

    def create_patch_baseline(
        self,
        context: RequestContext,
        name: BaselineName,
        operating_system: OperatingSystem = None,
        global_filters: PatchFilterGroup = None,
        approval_rules: PatchRuleGroup = None,
        approved_patches: PatchIdList = None,
        approved_patches_compliance_level: PatchComplianceLevel = None,
        approved_patches_enable_non_security: Boolean = None,
        rejected_patches: PatchIdList = None,
        rejected_patches_action: PatchAction = None,
        description: BaselineDescription = None,
        sources: PatchSourceList = None,
        available_security_updates_compliance_status: PatchComplianceStatus = None,
        client_token: ClientToken = None,
        tags: TagList = None,
        **kwargs,
    ) -> CreatePatchBaselineResult:
        return CreatePatchBaselineResult(**call_moto(context))

    def delete_patch_baseline(
        self, context: RequestContext, baseline_id: BaselineId, **kwargs
    ) -> DeletePatchBaselineResult:
        return DeletePatchBaselineResult(**call_moto(context))

    def describe_patch_baselines(
        self,
        context: RequestContext,
        filters: PatchOrchestratorFilterList = None,
        max_results: PatchBaselineMaxResults = None,
        next_token: NextToken = None,
        **kwargs,
    ) -> DescribePatchBaselinesResult:
        return DescribePatchBaselinesResult(**call_moto(context))

    def register_target_with_maintenance_window(
        self,
        context: RequestContext,
        window_id: MaintenanceWindowId,
        resource_type: MaintenanceWindowResourceType,
        targets: Targets,
        owner_information: OwnerInformation = None,
        name: MaintenanceWindowName = None,
        description: MaintenanceWindowDescription = None,
        client_token: ClientToken = None,
        **kwargs,
    ) -> RegisterTargetWithMaintenanceWindowResult:
        return RegisterTargetWithMaintenanceWindowResult(**call_moto(context))

    def deregister_target_from_maintenance_window(
        self,
        context: RequestContext,
        window_id: MaintenanceWindowId,
        window_target_id: MaintenanceWindowTargetId,
        safe: Boolean = None,
        **kwargs,
    ) -> DeregisterTargetFromMaintenanceWindowResult:
        return DeregisterTargetFromMaintenanceWindowResult(**call_moto(context))

    def describe_maintenance_window_targets(
        self,
        context: RequestContext,
        window_id: MaintenanceWindowId,
        filters: MaintenanceWindowFilterList = None,
        max_results: MaintenanceWindowMaxResults = None,
        next_token: NextToken = None,
        **kwargs,
    ) -> DescribeMaintenanceWindowTargetsResult:
        return DescribeMaintenanceWindowTargetsResult(**call_moto(context))

    def create_maintenance_window(
        self,
        context: RequestContext,
        name: MaintenanceWindowName,
        schedule: MaintenanceWindowSchedule,
        duration: MaintenanceWindowDurationHours,
        cutoff: MaintenanceWindowCutoff,
        allow_unassociated_targets: MaintenanceWindowAllowUnassociatedTargets,
        description: MaintenanceWindowDescription = None,
        start_date: MaintenanceWindowStringDateTime = None,
        end_date: MaintenanceWindowStringDateTime = None,
        schedule_timezone: MaintenanceWindowTimezone = None,
        schedule_offset: MaintenanceWindowOffset = None,
        client_token: ClientToken = None,
        tags: TagList = None,
        **kwargs,
    ) -> CreateMaintenanceWindowResult:
        return CreateMaintenanceWindowResult(**call_moto(context))

    def delete_maintenance_window(
        self, context: RequestContext, window_id: MaintenanceWindowId, **kwargs
    ) -> DeleteMaintenanceWindowResult:
        return DeleteMaintenanceWindowResult(**call_moto(context))

    def describe_maintenance_windows(
        self,
        context: RequestContext,
        filters: MaintenanceWindowFilterList = None,
        max_results: MaintenanceWindowMaxResults = None,
        next_token: NextToken = None,
        **kwargs,
    ) -> DescribeMaintenanceWindowsResult:
        return DescribeMaintenanceWindowsResult(**call_moto(context))

    def register_task_with_maintenance_window(
        self,
        context: RequestContext,
        window_id: MaintenanceWindowId,
        task_arn: MaintenanceWindowTaskArn,
        task_type: MaintenanceWindowTaskType,
        targets: Targets = None,
        service_role_arn: ServiceRole = None,
        task_parameters: MaintenanceWindowTaskParameters = None,
        task_invocation_parameters: MaintenanceWindowTaskInvocationParameters = None,
        priority: MaintenanceWindowTaskPriority = None,
        max_concurrency: MaxConcurrency = None,
        max_errors: MaxErrors = None,
        logging_info: LoggingInfo = None,
        name: MaintenanceWindowName = None,
        description: MaintenanceWindowDescription = None,
        client_token: ClientToken = None,
        cutoff_behavior: MaintenanceWindowTaskCutoffBehavior = None,
        alarm_configuration: AlarmConfiguration = None,
        **kwargs,
    ) -> RegisterTaskWithMaintenanceWindowResult:
        return RegisterTaskWithMaintenanceWindowResult(**call_moto(context))

    def deregister_task_from_maintenance_window(
        self,
        context: RequestContext,
        window_id: MaintenanceWindowId,
        window_task_id: MaintenanceWindowTaskId,
        **kwargs,
    ) -> DeregisterTaskFromMaintenanceWindowResult:
        return DeregisterTaskFromMaintenanceWindowResult(**call_moto(context))

    def describe_maintenance_window_tasks(
        self,
        context: RequestContext,
        window_id: MaintenanceWindowId,
        filters: MaintenanceWindowFilterList = None,
        max_results: MaintenanceWindowMaxResults = None,
        next_token: NextToken = None,
        **kwargs,
    ) -> DescribeMaintenanceWindowTasksResult:
        return DescribeMaintenanceWindowTasksResult(**call_moto(context))

    # utility methods below

    @staticmethod
    def _denormalize_param_name_in_response(param_result: Dict, param_name: str):
        result_name = param_result["Name"]
        if result_name != param_name and result_name.lstrip("/") == param_name.lstrip("/"):
            param_result["Name"] = param_name

    @staticmethod
    def _has_secrets(names: ParameterNameList) -> Boolean:
        maybe_secret = next(
            filter(lambda n: n.startswith(PARAM_PREFIX_SECRETSMANAGER), names), None
        )
        return maybe_secret is not None

    @staticmethod
    def _normalize_name(param_name: ParameterName, validate=False) -> ParameterName:
        if is_arn(param_name):
            resource_name = extract_resource_from_arn(param_name).replace("parameter/", "")
            # if the parameter name is only the root path we want to look up without the leading slash.
            # Otherwise, we add the leading slash
            if "/" in resource_name:
                resource_name = f"/{resource_name}"
            return resource_name

        if validate:
            if "//" in param_name or ("/" in param_name and not param_name.startswith("/")):
                raise InvalidParameterNameException()
        param_name = param_name.strip("/")
        param_name = param_name.replace("//", "/")
        if "/" in param_name:
            param_name = "/%s" % param_name
        return param_name

    @staticmethod
    def _get_secrets_information(
        account_id: str, region_name: str, name: ParameterName, resource_name: str
    ) -> Optional[GetParameterResult]:
        client = connect_to(aws_access_key_id=account_id, region_name=region_name).secretsmanager
        try:
            secret_info = client.get_secret_value(SecretId=resource_name)
            secret_info.pop("ResponseMetadata", None)
            created_date_timestamp = time.mktime(secret_info["CreatedDate"].timetuple())
            secret_info["CreatedDate"] = created_date_timestamp
            secret_info_lower = keys_to_lower(
                remove_attributes(copy.deepcopy(secret_info), ["ARN"])
            )
            secret_info_lower["ARN"] = secret_info["ARN"]
            result = {
                "Parameter": {
                    "SourceResult": json.dumps(secret_info_lower, default=str),
                    "Name": name,
                    "Value": secret_info.get("SecretString"),
                    "Type": "SecureString",
                    "LastModifiedDate": created_date_timestamp,
                }
            }
            return GetParameterResult(**result)
        except client.exceptions.ResourceNotFoundException:
            return None

    @staticmethod
    def _get_params_and_secrets(
        account_id: str, region_name: str, names: ParameterNameList
    ) -> GetParametersResult:
        ssm_client = connect_to(aws_access_key_id=account_id, region_name=region_name).ssm
        result = {"Parameters": [], "InvalidParameters": []}

        for name in names:
            if name.startswith(PARAM_PREFIX_SECRETSMANAGER):
                secret = SsmProvider._get_secrets_information(
                    account_id, region_name, name, name[len(PARAM_PREFIX_SECRETSMANAGER) + 1 :]
                )
                if secret is not None:
                    secret = secret["Parameter"]
                    result["Parameters"].append(secret)
                else:
                    result["InvalidParameters"].append(name)
            else:
                try:
                    param = ssm_client.get_parameter(Name=name)
                    param["Parameter"]["LastModifiedDate"] = time.mktime(
                        param["Parameter"]["LastModifiedDate"].timetuple()
                    )
                    result["Parameters"].append(param["Parameter"])
                except ssm_client.exceptions.ParameterNotFound:
                    result["InvalidParameters"].append(name)

        return GetParametersResult(**result)

    @staticmethod
    def _notify_event_subscribers(
        account_id: str, region_name: str, name: ParameterName, operation: str
    ):
        if not is_api_enabled("events"):
            LOG.warning(
                "Service 'events' is not enabled: skip emitting SSM event. "
                "Please check your 'SERVICES' configuration variable."
            )
            return
        """Publish an EventBridge event to notify subscribers of changes."""
        events = connect_to(aws_access_key_id=account_id, region_name=region_name).events
        detail = {"name": name, "operation": operation}
        event = {
            "Source": "aws.ssm",
            "Detail": json.dumps(detail),
            "DetailType": "Parameter Store Change",
        }
        events.put_events(Entries=[event])
