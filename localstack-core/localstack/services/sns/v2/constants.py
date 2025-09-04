import re

SNS_PROTOCOLS = [
    "http",
    "https",
    "email",
    "email-json",
    "sms",
    "sqs",
    "application",
    "lambda",
    "firehose",
]

VALID_SUBSCRIPTION_ATTR_NAME = [
    "DeliveryPolicy",
    "FilterPolicy",
    "FilterPolicyScope",
    "RawMessageDelivery",
    "RedrivePolicy",
    "SubscriptionRoleArn",
]

E164_REGEX = re.compile(r"^\+?[1-9]\d{1,14}$")
DUMMY_SUBSCRIPTION_PRINCIPAL = "arn:{partition}:iam::{account_id}:user/DummySNSPrincipal"
