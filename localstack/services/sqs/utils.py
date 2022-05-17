import re

from moto.sqs.exceptions import MessageAttributesInvalid
from moto.sqs.models import TRANSPORT_TYPE_ENCODINGS, Message

from localstack import constants
from localstack.utils.common import clone
from localstack.utils.urls import path_from_url


def is_sqs_queue_url(url):
    path = path_from_url(url).partition("?")[0]
    return re.match(r"^/(queue|%s)/[a-zA-Z0-9_-]+(.fifo)?$" % constants.TEST_AWS_ACCOUNT_ID, path)


def parse_message_attributes(
    querystring, key="MessageAttribute", base="", value_namespace="Value."
):
    message_attributes = {}
    index = 1
    while True:
        # Loop through looking for message attributes
        name_key = base + "{0}.{1}.Name".format(key, index)
        name = querystring.get(name_key)
        if not name:
            # Found all attributes
            break

        data_type_key = base + "{0}.{1}.{2}DataType".format(key, index, value_namespace)
        data_type = querystring.get(data_type_key)
        if not data_type:
            raise MessageAttributesInvalid(
                "The message attribute '{0}' must contain non-empty message attribute value.".format(
                    name[0]
                )
            )

        data_type_parts = data_type[0].split(".")
        if data_type_parts[0] not in [
            "String",
            "Binary",
            "Number",
        ]:
            raise MessageAttributesInvalid(
                "The message attribute '{0}' has an invalid message attribute type, the set of supported type prefixes is Binary, Number, and String.".format(
                    name[0]
                )
            )

        type_prefix = "String"
        if data_type_parts[0] == "Binary":
            type_prefix = "Binary"

        value_key = base + "{0}.{1}.{2}{3}Value".format(key, index, value_namespace, type_prefix)
        value = querystring.get(value_key)
        if not value:
            raise MessageAttributesInvalid(
                "The message attribute '{0}' must contain non-empty message attribute value for message attribute type '{1}'.".format(
                    name[0], data_type[0]
                )
            )

        message_attributes[name[0]] = {
            "data_type": data_type[0],
            type_prefix.lower() + "_value": value[0],
        }

        index += 1

    return message_attributes


def get_message_attributes_md5(req_data):
    req_data = clone(req_data)
    orig_types = {}
    for key, entry in dict(req_data).items():
        # Fix an issue in moto where data types like 'Number.java.lang.Integer' are
        # not supported: Keep track of the original data type, and temporarily change
        # it to the short form (e.g., 'Number'), before changing it back again.
        if key.endswith("DataType"):
            parts = entry.split(".")
            if len(parts) > 2:
                short_type_name = parts[0]
                full_type_name = entry
                attr_num = key.split(".")[1]
                attr_name = req_data["MessageAttribute.%s.Name" % attr_num]
                orig_types[attr_name] = full_type_name
                req_data[key] = [short_type_name]
                if full_type_name not in TRANSPORT_TYPE_ENCODINGS:
                    TRANSPORT_TYPE_ENCODINGS[full_type_name] = TRANSPORT_TYPE_ENCODINGS[
                        short_type_name
                    ]

    # moto parse_message_attributes(..) expects params to be passed as dict of lists
    req_data_lists = {k: [v] for k, v in req_data.items()}
    moto_message = Message("dummy_msg_id", "dummy_body")
    moto_message.message_attributes = parse_message_attributes(req_data_lists)
    for key, data_type in orig_types.items():
        moto_message.message_attributes[key]["data_type"] = data_type
    message_attr_hash = moto_message.attribute_md5

    return message_attr_hash
