import re
from string import ascii_letters, digits

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

MSG_ATTR_NAME_REGEX = re.compile(r"^(?!\.)(?!.*\.$)(?!.*\.\.)[a-zA-Z0-9_\-.]+$")
ATTR_TYPE_REGEX = re.compile(r"^(String|Number|Binary)\..+$")
VALID_MSG_ATTR_NAME_CHARS = set(ascii_letters + digits + "." + "-" + "_")


GCM_URL = "https://fcm.googleapis.com/fcm/send"

# Endpoint to access all the PlatformEndpoint sent Messages
PLATFORM_ENDPOINT_MSGS_ENDPOINT = "/_aws/sns/platform-endpoint-messages"
