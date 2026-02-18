import json
import logging
import re
from dataclasses import dataclass
from typing import Any

from botocore.exceptions import ClientError

from localstack.aws.connect import connect_to
from localstack.services.cloudformation.engine.parameters import resolve_ssm_parameter
from localstack.services.cloudformation.engine.validations import ValidationError
from localstack.services.cloudformation.v2.types import EngineParameter, engine_parameter_value
from localstack.utils.numbers import is_number

LOG = logging.getLogger(__name__)

# CloudFormation allows using dynamic references in `Fn::Sub` expressions, so we must make sure
# we don't capture the parameter usage by excluding ${} characters
REGEX_DYNAMIC_REF = re.compile(r"{{resolve:([^:]+):([^${}]+)}}")

SSM_PARAMETER_TYPE_RE = re.compile(
    r"^AWS::SSM::Parameter::Value<(?P<listtype>List<)?(?P<innertype>[^>]+)>?>$"
)


@dataclass
class DynamicReference:
    service_name: str
    reference_key: str


def extract_dynamic_reference(value: Any) -> DynamicReference | None:
    if isinstance(value, str):
        if dynamic_ref_match := REGEX_DYNAMIC_REF.search(value):
            return DynamicReference(dynamic_ref_match[1], dynamic_ref_match[2])
    return None


def perform_dynamic_reference_lookup(
    reference: DynamicReference, account_id: str, region_name: str
) -> str | None:
    # basic dynamic reference support
    # see: https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/dynamic-references.html
    # technically there are more restrictions for each of these services but checking each of these
    # isn't really necessary for the current level of emulation

    # only these 3 services are supported for dynamic references right now
    if reference.service_name == "ssm":
        ssm_client = connect_to(aws_access_key_id=account_id, region_name=region_name).ssm
        try:
            return ssm_client.get_parameter(Name=reference.reference_key)["Parameter"]["Value"]
        except ClientError as e:
            LOG.error("client error accessing SSM parameter '%s': %s", reference.reference_key, e)
            raise
    elif reference.service_name == "ssm-secure":
        ssm_client = connect_to(aws_access_key_id=account_id, region_name=region_name).ssm
        try:
            return ssm_client.get_parameter(Name=reference.reference_key, WithDecryption=True)[
                "Parameter"
            ]["Value"]
        except ClientError as e:
            LOG.error("client error accessing SSM parameter '%s': %s", reference.reference_key, e)
            raise
    elif reference.service_name == "secretsmanager":
        # reference key needs to be parsed further
        # because {{resolve:secretsmanager:secret-id:secret-string:json-key:version-stage:version-id}}
        # we match for "secret-id:secret-string:json-key:version-stage:version-id"
        # where
        #   secret-id can either be the secret name or the full ARN of the secret
        #   secret-string *must* be SecretString
        #   all other values are optional
        secret_id = reference.reference_key
        [json_key, version_stage, version_id] = [None, None, None]
        if "SecretString" in reference.reference_key:
            parts = reference.reference_key.split(":SecretString:")
            secret_id = parts[0]
            # json-key, version-stage and version-id are optional.
            [json_key, version_stage, version_id] = f"{parts[1]}::".split(":")[:3]

        kwargs = {}  # optional args for get_secret_value
        if version_id:
            kwargs["VersionId"] = version_id
        if version_stage:
            kwargs["VersionStage"] = version_stage

        secretsmanager_client = connect_to(
            aws_access_key_id=account_id, region_name=region_name
        ).secretsmanager
        try:
            secret_value = secretsmanager_client.get_secret_value(SecretId=secret_id, **kwargs)[
                "SecretString"
            ]
        except ClientError:
            LOG.error("client error while trying to access key '%s': %s", secret_id)
            raise

        if json_key:
            json_secret = json.loads(secret_value)
            if json_key not in json_secret:
                raise RuntimeError(
                    f"JSON value for {reference.service_name}.{reference.reference_key} not present"
                )
            return str(json_secret[json_key])
        else:
            return str(secret_value)

    LOG.warning(
        "Unsupported service for dynamic parameter: service_name=%s", reference.service_name
    )
    return None


def resolve_parameters(
    template: dict | None,
    parameters: dict | None,
    account_id: str,
    region_name: str,
    before_parameters: dict | None,
) -> dict[str, EngineParameter]:
    template_parameters = template.get("Parameters", {})
    resolved_parameters = {}
    invalid_parameters = []
    for name, parameter in template_parameters.items():
        given_value = parameters.get(name)
        default_value = parameter.get("Default")
        resolved_parameter = EngineParameter(
            type_=parameter["Type"],
            given_value=given_value,
            default_value=default_value,
            no_echo=parameter.get("NoEcho"),
        )

        # validate the type
        if parameter["Type"] == "Number" and not is_number(
            engine_parameter_value(resolved_parameter)
        ):
            raise ValidationError(f"Parameter '{name}' must be a number.")

        # TODO: support other parameter types
        if match := SSM_PARAMETER_TYPE_RE.match(parameter["Type"]):
            inner_type = match.group("innertype")
            is_list_type = match.group("listtype") is not None
            if is_list_type or inner_type == "CommaDelimitedList":
                # list types
                try:
                    resolved_value = resolve_ssm_parameter(
                        account_id, region_name, given_value or default_value
                    )
                    resolved_parameter["resolved_value"] = resolved_value.split(",")
                except Exception:
                    raise ValidationError(
                        f"Parameter {name} should either have input value or default value"
                    )
            else:
                try:
                    resolved_parameter["resolved_value"] = resolve_ssm_parameter(
                        account_id, region_name, given_value or default_value
                    )
                except Exception as e:
                    # we could not find the parameter however CDK provides the resolved value rather than the
                    # parameter name again so try to look up the value in the previous parameters
                    if (
                        before_parameters
                        and (before_param := before_parameters.get(name))
                        and isinstance(before_param, dict)
                        and (resolved_value := before_param.get("resolved_value"))
                    ):
                        LOG.debug(
                            "Parameter %s could not be resolved, using previous value of %s",
                            name,
                            resolved_value,
                        )
                        resolved_parameter["resolved_value"] = resolved_value
                    else:
                        raise ValidationError(
                            f"Parameter {name} should either have input value or default value"
                        ) from e
        elif given_value is None and default_value is None:
            invalid_parameters.append(name)
            continue

        resolved_parameters[name] = resolved_parameter

    if invalid_parameters:
        raise ValidationError(f"Parameters: [{','.join(invalid_parameters)}] must have values")

    for name, parameter in resolved_parameters.items():
        if (
            parameter.get("resolved_value") is None
            and parameter.get("given_value") is None
            and parameter.get("default_value") is None
        ):
            raise ValidationError(
                f"Parameter {name} should either have input value or default value"
            )

    return resolved_parameters
