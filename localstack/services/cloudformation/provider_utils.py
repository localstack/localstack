"""
A set of utils for use in resource providers.

Avoid any imports to localstack here and keep external imports to a minimum!
This is because we want to be able to package a resource provider without including localstack code.
"""
import uuid


def generate_default_name(stack_name: str, logical_resource_id: str):
    random_id_part = str(uuid.uuid4())[0:8]
    resource_id_part = logical_resource_id[:24]
    stack_name_part = stack_name[: 63 - 2 - (len(random_id_part) + len(resource_id_part))]
    return f"{stack_name_part}-{resource_id_part}-{random_id_part}"
