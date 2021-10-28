# NOTE: This code is deprecated and will be removed in a future iteration!
# FIXME: get_entity_id and update_physical_resource_id are used in the pro code. refactor there
#  and then remove here

import logging

# TODO: remove
from moto.apigateway import models as apigw_models
from moto.awslambda import models as lambda_models
from moto.dynamodb import models as dynamodb_models
from moto.dynamodb2 import models as dynamodb2_models
from moto.kinesis import models as kinesis_models

from localstack import config
from localstack.services.cloudformation import service_models
from localstack.utils.aws import aws_stack

from .models import elasticsearch, events, kinesisfirehose, logs, secretsmanager

LOG = logging.getLogger(__name__)


def get_entity_id(entity, resource_json=None):
    # check if physical_resource_id is present
    if hasattr(entity, "physical_resource_id"):
        return entity.physical_resource_id
    # check ID attribute candidates
    types_with_ref_as_id_or_name = (apigw_models.RestAPI, apigw_models.Resource)
    attr_candidates = ["function_arn", "Arn", "Ref", "id", "Id", "name", "Name"]
    for attr in attr_candidates:
        if hasattr(entity, attr):
            if attr in ["id", "name"] and not isinstance(entity, types_with_ref_as_id_or_name):
                LOG.warning(
                    'Unable to find ARN, using "%s" instead: %s - %s',
                    attr,
                    resource_json,
                    entity,
                )
            return getattr(entity, attr)
        if hasattr(entity, "get_cfn_attribute"):
            try:
                result = entity.get_cfn_attribute(attr)
                if result:
                    return result
            except Exception:
                pass
        if isinstance(entity, dict):
            if attr in entity:
                return entity.get(attr)
    # fall back to classes that use params as the dict of entity parameters
    if hasattr(entity, "params"):
        for key, value in (entity.params or {}).items():
            if key.endswith("Name"):
                return value


def update_physical_resource_id(resource):
    phys_res_id = getattr(resource, "physical_resource_id", None)
    if phys_res_id:
        return

    if isinstance(resource, lambda_models.LambdaFunction):
        func_arn = aws_stack.lambda_function_arn(resource.function_name)
        resource.function_arn = resource.physical_resource_id = func_arn

    elif isinstance(resource, service_models.StepFunctionsActivity):
        act_arn = aws_stack.stepfunctions_activity_arn(resource.params.get("Name"))
        resource.physical_resource_id = act_arn

    elif isinstance(resource, kinesis_models.Stream):
        resource.physical_resource_id = resource.stream_name

    elif isinstance(resource, logs.LogsLogGroup):
        resource.physical_resource_id = resource.params.get("LogGroupName")

    elif isinstance(resource, kinesisfirehose.FirehoseDeliveryStream):
        resource.physical_resource_id = resource.params.get("DeliveryStreamName")

    elif isinstance(resource, secretsmanager.SecretsManagerSecret):
        resource.physical_resource_id = resource.params.get("Name")

    elif isinstance(resource, events.EventsRule):
        resource.physical_resource_id = resource.params.get("Name")

    elif isinstance(resource, elasticsearch.ElasticsearchDomain):
        resource.physical_resource_id = resource.params.get("DomainName")

    elif isinstance(resource, secretsmanager.SecretsManagerSecret):
        secret = secretsmanager.SecretsManagerSecret.fetch_details(resource.props["Name"])
        if secret:
            resource.props["ARN"] = resource.physical_resource_id = secret["ARN"]

    elif isinstance(resource, dynamodb_models.Table):
        resource.physical_resource_id = resource.name

    elif isinstance(resource, dynamodb2_models.Table):
        resource.physical_resource_id = resource.name

    elif isinstance(resource, apigw_models.RestAPI):
        resource.physical_resource_id = resource.id

    elif isinstance(resource, apigw_models.Stage):
        resource.physical_resource_id = resource.get("stageName")

    elif isinstance(resource, apigw_models.Resource):
        resource.physical_resource_id = resource.id

    else:
        LOG.warning("Unable to determine physical_resource_id for resource %s" % type(resource))


def start_cloudformation(port=None, asynchronous=False):
    from localstack.services.cloudformation import cloudformation_api
    from localstack.services.infra import start_local_api

    port = port or config.PORT_CLOUDFORMATION
    return start_local_api(
        "CloudFormation",
        port,
        api="cloudformation",
        method=cloudformation_api.serve,
        asynchronous=asynchronous,
    )
