import copy
import json
import time
from abc import ABC
from typing import Dict, Optional

from localstack.aws.api import CommonServiceException, RequestContext
from localstack.aws.api.ssm import (
    Boolean,
    DeleteParameterResult,
    GetParameterResult,
    GetParametersResult,
    LabelParameterVersionResult,
    ParameterLabelList,
    ParameterName,
    ParameterNameList,
    PSParameterName,
    PSParameterVersion,
    PutParameterRequest,
    PutParameterResult,
    SsmApi,
)
from localstack.services.moto import call_moto, call_moto_with_request
from localstack.utils.aws import aws_stack
from localstack.utils.collections import remove_attributes
from localstack.utils.objects import keys_to_lower

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
    ) -> GetParametersResult:
        if SsmProvider._has_secrets(names):
            return SsmProvider._get_params_and_secrets(names)

        norm_names = list([SsmProvider._normalize_name(name, validate=True) for name in names])
        request = {"Names": norm_names, "WithDecryption": bool(with_decryption)}
        res = call_moto_with_request(context, request)

        if not res.get("InvalidParameters"):
            # note: simplifying assumption for now - only de-normalizing names if no invalid params were given
            for i in range(len(res["Parameters"])):
                self._denormalize_param_name_in_response(res["Parameters"][i], names[i])

        return GetParametersResult(**res)

    def put_parameter(
        self, context: RequestContext, request: PutParameterRequest
    ) -> PutParameterResult:
        name = request["Name"]
        nname = SsmProvider._normalize_name(name)
        if name != nname:
            request.update({"Name": nname})
            moto_res = call_moto_with_request(context, request)
        else:
            moto_res = call_moto(context)
        SsmProvider._notify_event_subscribers(nname, "Create")
        return PutParameterResult(**moto_res)

    def get_parameter(
        self,
        context: RequestContext,
        name: PSParameterName,
        with_decryption: Boolean = None,
    ) -> GetParameterResult:
        result = None

        norm_name = self._normalize_name(name, validate=True)
        details = norm_name.split("/")
        if len(details) > 4:
            service = details[3]
            if service == "secretsmanager":
                resource_name = "/".join(details[4:])
                result = SsmProvider._get_secrets_information(norm_name, resource_name)

        if not result:
            result = call_moto_with_request(
                context, {"Name": norm_name, "WithDecryption": bool(with_decryption)}
            )

        self._denormalize_param_name_in_response(result["Parameter"], name)

        return GetParameterResult(**result)

    def delete_parameter(
        self, context: RequestContext, name: PSParameterName
    ) -> DeleteParameterResult:
        SsmProvider._notify_event_subscribers(name, "Delete")
        call_moto(context)  # Return type is an emtpy type.
        return DeleteParameterResult()

    def label_parameter_version(
        self,
        context: RequestContext,
        name: PSParameterName,
        labels: ParameterLabelList,
        parameter_version: PSParameterVersion = None,
    ) -> LabelParameterVersionResult:
        SsmProvider._notify_event_subscribers(name, "LabelParameterVersion")
        return LabelParameterVersionResult(**call_moto(context))

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
        name: ParameterName, resource_name: str
    ) -> Optional[GetParameterResult]:
        client = aws_stack.connect_to_service("secretsmanager")
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
    def _get_params_and_secrets(names: ParameterNameList) -> GetParametersResult:
        ssm_client = aws_stack.connect_to_service("ssm")
        result = {"Parameters": [], "InvalidParameters": []}

        for name in names:
            if name.startswith(PARAM_PREFIX_SECRETSMANAGER):
                secret = SsmProvider._get_secrets_information(
                    name, name[len(PARAM_PREFIX_SECRETSMANAGER) + 1 :]
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
    def _notify_event_subscribers(name: ParameterName, operation: str):
        """Publish an EventBridge event to notify subscribers of changes."""
        events = aws_stack.connect_to_service("events")
        detail = {"name": name, "operation": operation}
        event = {
            "Source": "aws.ssm",
            "Detail": json.dumps(detail),
            "DetailType": "Parameter Store Change",
        }
        events.put_events(Entries=[event])
