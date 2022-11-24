import re

from moto.ec2 import ec2_backends

from localstack.aws.api.route53resolver import ResourceNotFoundException, ValidationException
from localstack.utils.strings import get_random_hex


def get_route53_resolver_firewall_rule_group_id():
    return f"rslvr-frg-{get_random_hex(17)}"


def get_route53_resolver_firewall_domain_list_id():
    return f"rslvr-fdl-{get_random_hex(17)}"


def get_route53_resolver_firewall_rule_group_association_id():
    return f"rslvr-frgassoc-{get_random_hex(17)}"


def get_resolver_query_log_config_id():
    return f"rslvr-rqlc-{get_random_hex(17)}"


def get_route53_resolver_query_log_config_association_id():
    return f"rslvr-qlcassoc-{get_random_hex(17)}"


def get_firewall_config_id():
    return f"rslvr-fc-{get_random_hex(17)}"


def validate_priority(priority):
    # value of priority can be null in case of update
    if priority:
        if priority not in range(100, 9900):
            raise ValidationException(
                f"[RSLVR-02017] The priority value you provided is reserved. Provide a number between '100' and '9900'. Trace Id: '{get_trace_id()}'"
            )


def validate_mutation_protection(mutation_protection):
    if mutation_protection:
        if mutation_protection not in ["ENABLED", "DISABLED"]:
            raise ValidationException(
                f"[RSLVR-02018] The mutation protection value you provided is reserved. Provide a value of 'ENABLED' or 'DISABLED'. Trace Id: '{get_trace_id()}'"
            )


def validate_destination_arn(destination_arn):
    arn_pattern = r"arn:aws:(kinesis|logs|s3):?(.*)"
    if not re.match(arn_pattern, destination_arn):
        raise ResourceNotFoundException(
            f"[RSLVR-01014] An Amazon Resource Name (ARN) for the destination is required. Trace Id: '{get_trace_id()}'"
        )


def validate_vpc(vpc_id: str, region: str, account_id: str):
    backend = ec2_backends[account_id][region]

    if vpc_id not in backend.vpcs:
        raise ValidationException(
            f"[RSLVR-02025] Can't find the resource with ID : '{vpc_id}'. Trace Id: '{get_trace_id()}'"
        )


def get_trace_id():
    return f"1-{get_random_hex(8)}-{get_random_hex(24)}"
