import logging
import re
from typing import Optional, TypedDict

from botocore.utils import ArnParser, InvalidArnException

from localstack.aws.accounts import get_aws_account_id
from localstack.utils.aws.aws_stack import connect_to_service, get_region, get_valid_regions

# set up logger
LOG = logging.getLogger(__name__)

# maps SQS queue ARNs to queue URLs
SQS_ARN_TO_URL_CACHE = {}

# TODO: extract ARN utils into separate file!

_arn_parser = ArnParser()


def sqs_queue_url_for_arn(queue_arn):
    if "://" in queue_arn:
        return queue_arn
    if queue_arn in SQS_ARN_TO_URL_CACHE:
        return SQS_ARN_TO_URL_CACHE[queue_arn]

    try:
        arn = parse_arn(queue_arn)
        region_name = arn["region"]
        queue_name = arn["resource"]
    except InvalidArnException:
        region_name = None
        queue_name = queue_arn

    sqs_client = connect_to_service("sqs", region_name=region_name)
    result = sqs_client.get_queue_url(QueueName=queue_name)["QueueUrl"]
    SQS_ARN_TO_URL_CACHE[queue_arn] = result
    return result


# TODO: remove and merge with sqs_queue_url_for_arn(..) above!!
def get_sqs_queue_url(queue_arn: str) -> str:
    return sqs_queue_url_for_arn(queue_arn)


class ArnData(TypedDict):
    partition: str
    service: str
    region: str
    account: str
    resource: str


def parse_arn(arn: str) -> ArnData:
    """
    Uses a botocore ArnParser to parse an arn.

    :param arn: the arn string to parse
    :returns: a dictionary containing the ARN components
    :raises InvalidArnException: if the arn is invalid
    """
    return _arn_parser.parse_arn(arn)


def extract_account_id_from_arn(arn: str) -> Optional[str]:
    try:
        return parse_arn(arn).get("account")
    except InvalidArnException:
        return None


def extract_region_from_arn(arn: str) -> Optional[str]:
    try:
        return parse_arn(arn).get("region")
    except InvalidArnException:
        return None


def extract_service_from_arn(arn: str) -> Optional[str]:
    try:
        return parse_arn(arn).get("service")
    except InvalidArnException:
        return None


def extract_resource_from_arn(arn: str) -> Optional[str]:
    try:
        return parse_arn(arn).get("resource")
    except InvalidArnException:
        return None


def role_arn(role_name, account_id=None, env=None):
    if not role_name:
        return role_name
    if role_name.startswith("arn:aws:iam::"):
        return role_name
    account_id = account_id or get_aws_account_id()
    return "arn:aws:iam::%s:role/%s" % (account_id, role_name)


def policy_arn(policy_name, account_id=None):
    if ":policy/" in policy_name:
        return policy_name
    account_id = account_id or get_aws_account_id()
    return "arn:aws:iam::{}:policy/{}".format(account_id, policy_name)


def iam_resource_arn(resource, role=None):
    if not role:
        role = f"role-{resource}"
    return role_arn(role_name=role, account_id=get_aws_account_id())


def secretsmanager_secret_arn(secret_id, account_id=None, region_name=None, random_suffix=None):
    if ":" in (secret_id or ""):
        return secret_id
    pattern = "arn:aws:secretsmanager:%s:%s:secret:%s"
    arn = _resource_arn(secret_id, pattern, account_id=account_id, region_name=region_name)
    if random_suffix:
        arn += f"-{random_suffix}"
    return arn


def cloudformation_stack_arn(stack_name, stack_id=None, account_id=None, region_name=None):
    stack_id = stack_id or "id-123"
    pattern = "arn:aws:cloudformation:%s:%s:stack/%s/{stack_id}".format(stack_id=stack_id)
    return _resource_arn(stack_name, pattern, account_id=account_id, region_name=region_name)


def cf_change_set_arn(change_set_name, change_set_id=None, account_id=None, region_name=None):
    change_set_id = change_set_id or "id-456"
    pattern = "arn:aws:cloudformation:%s:%s:changeSet/%s/{cs_id}".format(cs_id=change_set_id)
    return _resource_arn(change_set_name, pattern, account_id=account_id, region_name=region_name)


def dynamodb_table_arn(table_name, account_id=None, region_name=None):
    table_name = table_name.split(":table/")[-1]
    pattern = "arn:aws:dynamodb:%s:%s:table/%s"
    return _resource_arn(table_name, pattern, account_id=account_id, region_name=region_name)


def dynamodb_stream_arn(table_name, latest_stream_label, account_id=None):
    account_id = account_id or get_aws_account_id()
    return "arn:aws:dynamodb:%s:%s:table/%s/stream/%s" % (
        get_region(),
        account_id,
        table_name,
        latest_stream_label,
    )


def cloudwatch_alarm_arn(alarm_name, account_id=None, region_name=None):
    pattern = "arn:aws:cloudwatch:%s:%s:alarm:%s"
    return _resource_arn(alarm_name, pattern, account_id=account_id, region_name=region_name)


def log_group_arn(group_name, account_id=None, region_name=None):
    pattern = "arn:aws:logs:%s:%s:log-group:%s"
    return _resource_arn(group_name, pattern, account_id=account_id, region_name=region_name)


def events_rule_arn(rule_name, account_id=None, region_name=None):
    pattern = "arn:aws:events:%s:%s:rule/%s"
    return _resource_arn(rule_name, pattern, account_id=account_id, region_name=region_name)


def event_bus_arn(bus_name, account_id=None, region_name=None):
    pattern = "arn:aws:events:%s:%s:event-bus/%s"
    return _resource_arn(bus_name, pattern, account_id=account_id, region_name=region_name)


def lambda_function_arn(function_name, account_id=None, region_name=None):
    return lambda_function_or_layer_arn(
        "function", function_name, account_id=account_id, region_name=region_name
    )


def lambda_layer_arn(layer_name, version=None, region_name=None, account_id=None):
    return lambda_function_or_layer_arn(
        "layer", layer_name, version=None, account_id=account_id, region_name=region_name
    )


def lambda_function_or_layer_arn(
    type, entity_name, version=None, account_id=None, region_name=None
):
    pattern = "arn:([a-z-]+):lambda:.*:.*:(function|layer):.*"
    if re.match(pattern, entity_name):
        return entity_name
    if ":" in entity_name:
        client = connect_to_service("lambda")
        entity_name, _, alias = entity_name.rpartition(":")
        try:
            alias_response = client.get_alias(FunctionName=entity_name, Name=alias)
            version = alias_response["FunctionVersion"]

        except Exception as e:
            msg = f"Alias {alias} of {entity_name} not found"
            LOG.info(f"{msg}: {e}")
            raise Exception(msg)

    account_id = account_id or get_aws_account_id()
    region_name = region_name or get_region()
    result = f"arn:aws:lambda:{region_name}:{account_id}:{type}:{entity_name}"
    if version:
        result = f"{result}:{version}"
    return result


def lambda_function_name(name_or_arn):
    if ":" in name_or_arn:
        arn = parse_arn(name_or_arn)
        if arn["service"] != "lambda":
            raise ValueError("arn is not a lambda arn %s" % name_or_arn)

        return parse_arn(name_or_arn)["resource"].split(":")[1]
    else:
        return name_or_arn


def state_machine_arn(name, account_id=None, region_name=None):
    pattern = "arn:aws:states:%s:%s:stateMachine:%s"
    return _resource_arn(name, pattern, account_id=account_id, region_name=region_name)


def stepfunctions_activity_arn(name, account_id=None, region_name=None):
    pattern = "arn:aws:states:%s:%s:activity:%s"
    return _resource_arn(name, pattern, account_id=account_id, region_name=region_name)


def fix_arn(arn):
    """Function that attempts to "canonicalize" the given ARN. This includes converting
    resource names to ARNs, replacing incorrect regions, account IDs, etc."""
    if arn.startswith("arn:aws:lambda"):
        parts = arn.split(":")
        region = parts[3] if parts[3] in get_valid_regions() else get_region()
        return lambda_function_arn(lambda_function_name(arn), region_name=region)
    LOG.warning("Unable to fix/canonicalize ARN: %s", arn)
    return arn


def cognito_user_pool_arn(user_pool_id, account_id=None, region_name=None):
    pattern = "arn:aws:cognito-idp:%s:%s:userpool/%s"
    return _resource_arn(user_pool_id, pattern, account_id=account_id, region_name=region_name)


def kinesis_stream_arn(stream_name, account_id=None, region_name=None):
    pattern = "arn:aws:kinesis:%s:%s:stream/%s"
    return _resource_arn(stream_name, pattern, account_id=account_id, region_name=region_name)


def elasticsearch_domain_arn(domain_name, account_id=None, region_name=None):
    pattern = "arn:aws:es:%s:%s:domain/%s"
    return _resource_arn(domain_name, pattern, account_id=account_id, region_name=region_name)


def firehose_stream_arn(stream_name, account_id=None, region_name=None):
    pattern = "arn:aws:firehose:%s:%s:deliverystream/%s"
    return _resource_arn(stream_name, pattern, account_id=account_id, region_name=region_name)


def es_domain_arn(domain_name, account_id=None, region_name=None):
    pattern = "arn:aws:es:%s:%s:domain/%s"
    return _resource_arn(domain_name, pattern, account_id=account_id, region_name=region_name)


def kms_key_arn(key_id: str, account_id: str = None, region_name: str = None) -> str:
    pattern = "arn:aws:kms:%s:%s:key/%s"
    return _resource_arn(key_id, pattern, account_id=account_id, region_name=region_name)


def kms_alias_arn(alias_name: str, account_id: str = None, region_name: str = None):
    if not alias_name.startswith("alias/"):
        alias_name = "alias/" + alias_name
    pattern = "arn:aws:kms:%s:%s:%s"
    return _resource_arn(alias_name, pattern, account_id=account_id, region_name=region_name)


def code_signing_arn(code_signing_id: str, account_id: str = None, region_name: str = None) -> str:
    pattern = "arn:aws:lambda:%s:%s:code-signing-config:%s"
    return _resource_arn(code_signing_id, pattern, account_id=account_id, region_name=region_name)


def ssm_parameter_arn(param_name: str, account_id: str = None, region_name: str = None) -> str:
    pattern = "arn:aws:ssm:%s:%s:parameter/%s"
    param_name = param_name.lstrip("/")
    return _resource_arn(param_name, pattern, account_id=account_id, region_name=region_name)


def s3_bucket_arn(bucket_name_or_arn: str, account_id=None):
    bucket_name = s3_bucket_name(bucket_name_or_arn)
    return "arn:aws:s3:::%s" % bucket_name


def s3_bucket_name(bucket_name_or_arn: str) -> str:
    return bucket_name_or_arn.split(":::")[-1]


def _resource_arn(name: str, pattern: str, account_id: str = None, region_name: str = None) -> str:
    if ":" in name:
        return name
    account_id = account_id or get_aws_account_id()
    region_name = region_name or get_region()
    if len(pattern.split("%s")) == 3:
        return pattern % (account_id, name)
    return pattern % (region_name, account_id, name)


def sqs_queue_arn(queue_name, account_id=None, region_name=None):
    account_id = account_id or get_aws_account_id()
    region_name = region_name or get_region()
    queue_name = queue_name.split("/")[-1]
    return "arn:aws:sqs:%s:%s:%s" % (region_name, account_id, queue_name)


def apigateway_restapi_arn(api_id, account_id=None, region_name=None):
    account_id = account_id or get_aws_account_id()
    region_name = region_name or get_region()
    return "arn:aws:apigateway:%s:%s:/restapis/%s" % (region_name, account_id, api_id)


def sqs_queue_name(queue_arn):
    if ":" in queue_arn:
        return parse_arn(queue_arn)["resource"]
    else:
        return queue_arn


def sns_topic_arn(topic_name, account_id=None):
    account_id = account_id or get_aws_account_id()
    return "arn:aws:sns:%s:%s:%s" % (get_region(), account_id, topic_name)


def firehose_name(firehose_arn):
    return firehose_arn.split("/")[-1]


def opensearch_domain_name(domain_arn: str) -> str:
    return domain_arn.rpartition("/")[2]


def kinesis_stream_name(kinesis_arn):
    return kinesis_arn.split(":stream/")[-1]


def apigateway_invocations_arn(lambda_uri, region_name: str = None):
    return "arn:aws:apigateway:%s:lambda:path/2015-03-31/functions/%s/invocations" % (
        region_name or get_region(),
        lambda_uri,
    )


def get_ecr_repository_arn(name, account_id=None, region_name=None):
    pattern = "arn:aws:ecr:%s:%s:repository/%s"
    return _resource_arn(name, pattern, account_id=account_id, region_name=region_name)


def get_route53_resolver_firewall_rule_group_arn(
    id: str, account_id: str = None, region_name: str = None
):
    pattern = "arn:aws:route53resolver:%s:%s:firewall-rule-group/%s"
    return _resource_arn(id, pattern, account_id=account_id, region_name=region_name)


def get_route53_resolver_firewall_domain_list_arn(
    id: str, account_id: str = None, region_name: str = None
):
    pattern = "arn:aws:route53resolver:%s:%s:firewall-domain-list/%s"
    return _resource_arn(id, pattern, account_id=account_id, region_name=region_name)


def get_route53_resolver_firewall_rule_group_associations_arn(
    id: str, account_id: str = None, region_name: str = None
):
    pattern = "arn:aws:route53resolver:%s:%s:firewall-rule-group-association/%s"
    return _resource_arn(id, pattern, account_id=account_id, region_name=region_name)


def get_resolver_query_log_config_arn(id: str, account_id: str = None, region_name: str = None):
    pattern = "arn:aws:route53resolver:%s:%s:resolver-query-log-config/%s"
    return _resource_arn(id, pattern, account_id=account_id, region_name=region_name)
