from localstack.aws.api.route53resolver import ValidationException
from localstack.utils.aws import aws_stack
from localstack.utils.strings import get_random_hex


def get_route53_resolver_firewall_rule_group_id():
    return f"rslvr-frg-{get_random_hex(17)}"


def get_route53_resolver_firewall_domain_list_id():
    return f"rslvr-fdl-{get_random_hex(17)}"


def get_route53_resolver_firewall_rule_group_association_id():
    return f"rslvr-frgassoc-{get_random_hex(17)}"


def validate_priority(priority):
    # value of priority can be null in case of update
    if priority:
        if priority not in range(100, 9900):
            raise ValidationException(
                f"[RSLVR-02017] The priority value you provided is reserved. Provide a number between '100' and '9900'. Trace Id: '{aws_stack.get_trace_id()}'"
            )


def validate_mutation_protection(mutation_protection):
    if mutation_protection:
        if mutation_protection not in ["ENABLED", "DISABLED"]:
            raise ValidationException(
                f"[RSLVR-02018] The mutation protection value you provided is reserved. Provide a value of 'ENABLED' or 'DISABLED'. Trace Id: '{aws_stack.get_trace_id()}'"
            )
